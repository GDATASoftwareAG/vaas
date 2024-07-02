<?php

namespace VaasTesting;

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use React\EventLoop\Loop;
use React\Http\Browser;
use React\Stream\ReadableResourceStream;
use React\Stream\ReadableStreamInterface;
use React\Stream\ThroughStream;
use React\Stream\Util;
use React\Stream\WritableResourceStream;

use function React\Async\await;
use function React\Promise\Stream\buffer;

final class StreamsInLoopTest extends TestCase
{
    use ProphecyTrait;

    public function testLoopUnexpectedConsumesStreamWithBrowser() {
        $browser1 = new Browser();
        $browser2 = new Browser();

        $response1 = await($browser1->requestStreaming("GET", "https://secure.eicar.org/eicar.com.txt"));
        $body1 = $response1->getBody();
        $this->assertEquals(true, $body1->isReadable());

        $response2 = await($browser2->requestStreaming("GET", "https://secure.eicar.org/eicar.com.txt"));
        $this->assertEquals(false, $body1->isReadable());
        $body2 = $response2->getBody();
        $this->assertEquals(true, $body2->isReadable());
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