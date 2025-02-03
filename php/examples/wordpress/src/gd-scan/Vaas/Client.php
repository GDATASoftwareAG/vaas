<?php

namespace WpGdScan\Vaas;

use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;

class Client
{
    private Vaas $vaas;

    public function __construct()
    {
        $authenticator = new ClientCredentialsGrantAuthenticator(
            getenv("CLIENT_ID"),
            getenv("CLIENT_SECRET"),
            getenv("TOKEN_URL") ?: "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
        );
        $this->vaas = (new Vaas())
            ->withAuthenticator($authenticator)
            ->build();
    }

    public function scanSingleFile(string $fileName): void
    {
        file_put_contents(\plugin_dir_path(__FILE__) . "/log", "Filename: $fileName\n", FILE_APPEND);

        file_put_contents(\plugin_dir_path(__FILE__) . "/log", "Try to get Verdict: $fileName\n", FILE_APPEND);

        if ($this->vaas->ForFile($fileName) == \VaasSdk\Message\Verdict::MALICIOUS) {
            file_put_contents(
                \plugin_dir_path(__FILE__) . "/log",
                \VaasSdk\Message\Verdict::MALICIOUS . ": $fileName\n",
                FILE_APPEND
            );
            \update_option("gd_scan_found_malware", true);
            $fileList = $this->readFromFileDb();
            if (!in_array($fileName, $fileList)) {
                array_push($fileList, $fileName);
                $this->saveToDb($fileList);
            }
        } else {
            file_put_contents(\plugin_dir_path(__FILE__) . "/log", "Not Malicious: $fileName\n", FILE_APPEND);
        }
    }

    public function readFromFileDb(): array
    {
        if (!file_exists(\plugin_dir_path(__FILE__) . "/db")) {
            file_put_contents(\plugin_dir_path(__FILE__) . "/db", "[]");
        }
        $logs = file_get_contents(\plugin_dir_path(__FILE__) . "/db");
        return json_decode($logs);
    }

    public function saveToDb(array $fileList): void
    {
        file_put_contents(\plugin_dir_path(__FILE__) . "/db", json_encode($fileList));
    }
}
