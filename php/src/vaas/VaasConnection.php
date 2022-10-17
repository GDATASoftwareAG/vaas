<?php

namespace VaasSdk;

use VaasSdk\Exceptions\VaasConnectionClosedException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use WebSocket\Client;

class VaasConnection
{
    public Client $WebSocketClient;
    public string $SessionId;

    public function __construct(string $url, Client $WebSocketClient = null)
    {
        if (!isset($WebSocketClient))
            $this->WebSocketClient = new Client($url);
        else 
            $this->WebSocketClient = $WebSocketClient;
        $this->WebSocketClient->ping();
    }

    public function GetConnectedWebsocket()
    {
        if (!$this->WebSocketClient) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        if (!$this->WebSocketClient->isConnected()) {
            throw new VaasConnectionClosedException();
        }
        return $this->WebSocketClient;
    }

    public function GetAuthenticatedWebsocket()
    {
        $websocket = $this->GetConnectedWebsocket();
        if (!isset($this->SessionId) || !$this->SessionId) {
            throw new VaasInvalidStateException(
                "Not yet authenticated - connect() was not awaited"
                );
        }
        return $websocket;
    }
}