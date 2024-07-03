<?php

namespace VaasTesting;

use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request as ClientRequest;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;

final class StreamsInLoopTest extends TestCase
{
    use ProphecyTrait;

    public function testLoopUnexpectedConsumesStreamWithAmphp() {
        $browser1 = HttpClientBuilder::buildDefault();
        $browser2 = HttpClientBuilder::buildDefault();

        $response1 = $browser1->request(new ClientRequest("https://secure.eicar.org/eicar.com.txt", "GET"));
        $bodyStream1 = $response1->getBody();
        $this->assertTrue($bodyStream1->isReadable());

        $response2 = $browser2->request(new ClientRequest("https://secure.eicar.org/eicar.com", "GET"));
        $bodyStream2 = $response2->getBody();
        $this->assertTrue($bodyStream1->isReadable());
    }



    static function random_strings($length_of_string) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $characters_length = strlen($characters);
        $random_string = '';

        // Generate random characters until the string reaches desired length
        for ($i = 0; $i < $length_of_string; $i++) {
            $random_index = random_int(0, $characters_length - 1);
            $random_string .= $characters[$random_index];
        }

        return $random_string;
    }
}