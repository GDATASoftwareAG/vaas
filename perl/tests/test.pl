#!/usr/bin/perl
use FindBin;
use File::Spec;
use lib File::Spec->catdir( $FindBin::Bin, "..", "src" );
use VaaS;

use Test::Simple tests => 4;

#important: .env has to be like CLIENT_ID=example-id not CLIENT_ID="example-id"
my %credentials = get_env();

my $vaas_url = $credentials{'VAAS_URL'};
my $token_endpoint = $credentials{'TOKEN_URL'};
my $client_id = $credentials{'CLIENT_ID'};
my $client_secret = $credentials{'CLIENT_SECRET'};

my $vaas = new VaaS();

$vaas->connect_with_credentials($client_id, $client_secret, $token_endpoint, $vaas_url);

#Get verdict 'Clean' for sha256
ok(
    $vaas->get_verdict_by_sha256(
        "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23") eq
    "Clean",
    "Got verdict 'Clean' for sha256\n"
);

#Get verdict 'Malicious' for eicar
ok(
    $vaas->get_verdict_by_sha256(
        "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c") eq
    "Malicious",
    "Got verdict 'Malicious' for sha256\n"
);

#Get verdict 'Clean' for random file
my @set = ('A' .. 'Z');
my $random_str = join '' => map $set[rand @set], 1 .. 512; 

create_file(testfile, $random_string);

ok(
    $vaas->get_verdict_by_file('testfile') eq
    "Clean",
    "Got verdict 'Clean' for random testfile\n"
);

unlink(testfile);

#Get verdict 'Malicious' for eicar file
my $eicar = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=";

create_file(eicarfile, $eicar);

ok(
    $vaas->get_verdict_by_file('eicarfile') eq
    "Malicious",
    "Got verdict 'Malicious' for eicar file\n"
);

unlink(eicarfile);


sub get_env {
    open my $env, '<', File::Spec->catdir( $FindBin::Bin, "../.env" )
    or die "Unable to open file:$!\n";
    my %credentials = map { split /=|\s+/; } <$env>;

    close $env;

    return %credentials;
}

sub create_file {
    my $file = shift;
    my $buffer = shift;

    unless(open FILE, '>'.$file) {
        die "\nUnable to create $file\n";
    }
    
    print FILE $buffer;

    close FILE;
}
