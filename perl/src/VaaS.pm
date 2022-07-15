package VaaS;

=head1 NAME
Verdict-as-a-Service
'VaaS' is a Perl module for the VaaS-API.
=cut 

use warnings;
use strict;
use JSON;
use IO::Async::Loop;
use Cwd;
use lib getcwd;
use IO::Socket::SSL;
use IO::Select;
use Protocol::WebSocket::Client;
use UUID4::Tiny qw/create_uuid_string/;
use Furl;
use Digest::SHA qw(sha256_hex);

sub new {
    my $class = shift;

    my $self = {
        'debug'         => 0,
        'ws_client'     => undef,
        'http_client'   => undef,
        'tcp_socket'    => undef,
        'authenticated' => 3, #0 equals access denied and 1 equals authenticated
        'session_id'    => "",
        'got_verdict'   => 0,
        'verdict'       => "",
        'token'         => "",
        'upload_token'  => "",
        'upload_url'    => ""
    };

    bless $self, $class;

    return $self;
}

sub connect_with_credentials {
    my $self = shift;
    my $client_id = shift;
    my $client_secret = shift;
    my $token_endpoint = shift;
    my $vaas_url = shift;

    my $access_token = $self->_authenticate($client_id, $client_secret, $token_endpoint);

    return $self->connect($access_token, $vaas_url);
}

sub connect {
    my $self = shift;
    my $token = shift;
    my $url = shift;

    $self->_create_websocket_connection($url, $token);

    while ($self->{'authenticated'} == 3) {
        $self->_receive_data();
    }

    return $self->{'authenticated'};
}

sub _create_websocket_connection{
    my $self = shift;
    my $url = shift;
    my $token = shift;

    $self->_create_tcp_socket($url);

    $self->{'ws_client'} = Protocol::WebSocket::Client->new(url => $url);
    
    $self->{'ws_client'}->on(
        write => sub {
            my $ws_client = shift;
            my ($buf) = @_;

            syswrite $self->{'tcp_socket'}, $buf;
        }
    );

    $self->{'ws_client'}->on(
        connect => sub {
            my $ws_client    = shift;
            my %auth_request = (
                kind  => "AuthRequest",
                token => $token,
            );

            my $auth_request_json = encode_json \%auth_request;
            $ws_client->write($auth_request_json);
        }
    );

    $self->{'ws_client'}->on(
        read => sub {
            my $ws_client = shift;
            my ($buf) = @_;
            
            $self->_response_handler(@_);
        }
    );

    $self->{'ws_client'}->connect;
}

sub _create_tcp_socket{
    my $self = shift;
    my $url = shift;

    $url =~ m/(?<host>[^\/:]+)$/;

    $self->{'tcp_socket'} =  IO::Socket::SSL->new(
        PeerAddr           => $+{host},
        PeerPort           => "wss(443)",
        Proto              => 'tcp',
        SSL_startHandshake => 1,
        Blocking           => 1
    ) or die "Failed to connect to socket: $@";
}

sub _authenticate {
    my $self = shift;
    my $client_id = shift;
    my $client_secret = shift;
    my $token_endpoint = shift;

    $self->{'http_client'} = Furl->new();
    my $response = $self->{'http_client'}->post($token_endpoint, [], [grant_type=>'client_credentials',client_id=>$client_id,client_secret=>$client_secret]);

    if ($response->is_success) {
        my $response_ref  = decode_json($response->body);
        my %response_hash = %$response_ref;

        return $response_hash{'access_token'};

    } else {
        print "Error: ", $response->code, $response->message, "\n";
    }
}

sub get_verdict_by_sha256 {
    my $self   = shift;
    my $sha256 = $_[0];

    if ($self->{'authenticated'} == 1) {
        my $verdict_request = $self->_create_verdict_request($sha256);
        $self->{'ws_client'}->write($verdict_request);

        return $self->_get_verdict();
    } else {
        print "Error: not authenticated\n";
    }
}

sub get_verdict_by_file {
    my $self   = shift;
    my $path   = shift;

    if ($self->{'authenticated'} == 1) {
        my $buffer = $self->_read_file($path);

        my $sha256 = sha256_hex($buffer);
        my $verdict = $self->get_verdict_by_sha256($sha256);

        if($verdict eq "Unknown"){
            $self->_upload($buffer);
            $verdict = $self->_get_verdict();
        }

        return $verdict;
    } else {
        print "Error: not authenticated\n";
    }
}

sub _upload {
    my $self = shift;
    my $buffer = shift;
    
    my $response = $self->{'http_client'}->put($self->{'upload_url'}, [Authorization=>$self->{'upload_token'}], $buffer);

    if ($self->{'debug'} == 1){
        if ($response->is_success) {
            print "Upload successful.\n";
        } else {
            print "Status:  ", $response->code, "\n";
            print "Message: ", $response->message, "\n";
        }
    }
}

sub _read_file{
    my $self = shift;
    my $path = shift;

    open IN_DATA, '<', $path or die "cannot open file " . $path . " for reading: $!";
    my $buffer;
    
    {local $/; $buffer = <IN_DATA>;}
    close IN_DATA;

    return $buffer
}

sub _get_verdict{
    my $self = shift;
    $self->{'got_verdict'} = 0;

    while (!$self->{'got_verdict'}) {
        $self->_receive_data();
    }
    $self->{'got_verdict'} = 0;

    return $self->{'verdict'};
}

sub _receive_data{
    my $self = shift;

    my $recv_data;
    sysread $self->{'tcp_socket'}, $recv_data, 16384;
    $self->{'ws_client'}->read($recv_data);
}

sub _create_verdict_request {
    my $self   = shift;
    my $sha256 = $_[0];

    my %request = (
        sha256     => $sha256,
        kind       => "VerdictRequest",
        session_id => $self->{'session_id'},
        guid       => create_uuid_string
    );

    my $request_json = encode_json \%request;

    return $request_json;
}

sub _response_handler {
    my $self     = shift;
    my $response = $_[0];

    my $response_ref  = decode_json($response);
    my %response_hash = %$response_ref;

    if ($response_hash{'kind'} eq "AuthResponse") {
        $self->{'authenticated'} = $response_hash{'success'};
        $self->{'session_id'}    = $response_hash{'session_id'};
    }
    if ($response_hash{'kind'} eq "VerdictResponse") {
        $self->{'got_verdict'} = 1;
        $self->{'verdict'}     = $response_hash{'verdict'};

        if($response_hash{'verdict'} eq "Unknown"){
            $self->{'upload_token'} = $response_hash{'upload_token'};
            $self->{'upload_url'} = $response_hash{'url'};
        }
    }
}

1;
