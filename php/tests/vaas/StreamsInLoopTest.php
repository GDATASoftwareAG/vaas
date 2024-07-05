<?php

namespace VaasTesting;

use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request as ClientRequest;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;

/**
 * This test is just for making sure that streams are not just randomly consumed
 * it was the behaviour of reactphp so I wanted to make sure the same thing does not 
 * happen with amphp
 * 
 * With reactphp the stream was basically consumed at some point because it 
 * began consuming it internally the moment data came in.
 * 
 * So when requesting a stream and then doing some time "intensive" stuff before
 * putting the stream to a post request lead to the stream already been closed.
**/
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
}