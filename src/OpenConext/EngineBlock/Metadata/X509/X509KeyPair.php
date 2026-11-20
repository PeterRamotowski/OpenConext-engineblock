<?php

/**
 * Copyright 2010 SURFnet B.V.
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

namespace OpenConext\EngineBlock\Metadata\X509;

use RuntimeException;

/**
 * One of EngineBlock's key pairs for metadata and certificate publication. A local key pair holds its private key
 * file; a Private Key Agent key pair holds only the certificate.
 */
class X509KeyPair
{
    /**
     * @var X509Certificate
     */
    private $certificate;

    /**
     * @var X509PrivateKey|null
     */
    private $private;

    private bool $usesPrivateKeyAgent;

    /**
     * @throws RuntimeException when an agent key pair lacks a certificate or has a private key
     */
    public function __construct(
        ?X509Certificate $certificate = null,
        ?X509PrivateKey $private = null,
        bool $usesPrivateKeyAgent = false
    ) {
        if ($usesPrivateKeyAgent && ($certificate === null || $private !== null)) {
            throw new RuntimeException(
                'A private key agent key pair requires a certificate and must not have a local private key'
            );
        }

        $this->certificate = $certificate;
        $this->private = $private;
        $this->usesPrivateKeyAgent = $usesPrivateKeyAgent;
    }

    public static function forPrivateKeyAgent(X509Certificate $certificate): self
    {
        return new self($certificate, null, true);
    }

    /**
     * @return X509Certificate
     */
    public function getCertificate()
    {
        return $this->certificate;
    }

    /**
     * @return X509PrivateKey|null Always null for a private key agent key pair
     */
    public function getPrivateKey()
    {
        return $this->private;
    }

    public function usesPrivateKeyAgent(): bool
    {
        return $this->usesPrivateKeyAgent;
    }
}
