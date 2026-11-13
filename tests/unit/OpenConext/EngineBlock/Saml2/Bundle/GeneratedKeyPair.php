<?php declare(strict_types=1);

/**
 * Copyright 2026 SURFnet B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace OpenConext\EngineBlock\Saml2\Bundle;

use RuntimeException;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;

/**
 * Self-signed RSA key pairs for the bundle adapter tests, generated once per name and process.
 */
final class GeneratedKeyPair
{
    /**
     * @var array<string, self>
     */
    private static array $pairs = [];

    private function __construct(
        private readonly string $privateKeyPem,
        private readonly string $certificatePem,
    ) {
    }

    public static function named(string $name): self
    {
        return self::$pairs[$name] ??= self::generate($name);
    }

    public function privateKey(): PrivateKey
    {
        return new PrivateKey(PEM::fromString($this->privateKeyPem));
    }

    public function certificate(): X509Certificate
    {
        return new X509Certificate(PEM::fromString($this->certificatePem));
    }

    public function privateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    /**
     * The base64 certificate without PEM delimiters, as found in SAML metadata.
     */
    public function certificateData(): string
    {
        return preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $this->certificatePem);
    }

    private static function generate(string $name): self
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = $key === false ? false : openssl_csr_new(['commonName' => $name], $key, ['digest_alg' => 'sha256']);
        $certificate = $csr === false ? false : openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        if ($certificate === false
            || !openssl_pkey_export($key, $privateKeyPem)
            || !openssl_x509_export($certificate, $certificatePem)
        ) {
            throw new RuntimeException(sprintf('Could not generate the "%s" test key pair', $name));
        }

        return new self($privateKeyPem, $certificatePem);
    }
}
