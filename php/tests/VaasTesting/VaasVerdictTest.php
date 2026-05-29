<?php

namespace VaasTesting;

use PHPUnit\Framework\TestCase;
use VaasSdk\VaasVerdict;
use VaasSdk\Verdict;

final class VaasVerdictTest extends TestCase
{
    public function testFrom_WithEncryptedVerdict_PopulatesEncryptedFlag(): void
    {
        $verdict = VaasVerdict::from([
            'sha256' => '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            'verdict' => Verdict::CLEAN->value,
            'detection' => null,
            'fileType' => 'Zip',
            'mimeType' => 'application/zip',
            'isEncrypted' => true,
        ]);

        $this->assertSame(Verdict::CLEAN, $verdict->verdict);
        $this->assertTrue($verdict->isEncrypted);
        $this->assertSame('Zip', $verdict->fileType);
    }

    public function testToString_IncludesEncryptedFlag(): void
    {
        $verdict = VaasVerdict::from([
            'sha256' => '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            'verdict' => Verdict::MALICIOUS->value,
            'isEncrypted' => true,
        ]);

        $this->assertJsonStringEqualsJsonString(
            json_encode([
                'sha256' => '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
                'verdict' => Verdict::MALICIOUS->value,
                'detection' => null,
                'fileType' => null,
                'mimeType' => null,
                'isEncrypted' => true,
            ]),
            (string) $verdict
        );
    }
}