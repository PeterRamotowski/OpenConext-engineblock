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

/**
 * One of EngineBlock's key pairs. A local key pair holds its private key file; a Private Key Agent key pair holds
 * only the certificate, and the agent performs its private-key operations.
 */
class EngineBlock_X509_KeyPair
{
    /**
     * @var EngineBlock_X509_Certificate
     */
    private $certificate;

    /**
     * @var EngineBlock_X509_PrivateKey|null
     */
    private $private;

    private bool $usesPrivateKeyAgent;

    public function __construct(
        ?EngineBlock_X509_Certificate $certificate = null,
        ?EngineBlock_X509_PrivateKey $private = null,
        bool $usesPrivateKeyAgent = false
    ) {
        if ($usesPrivateKeyAgent && ($certificate === null || $private !== null)) {
            throw new EngineBlock_Exception(
                'A private key agent key pair requires a certificate and must not have a local private key'
            );
        }

        $this->certificate = $certificate;
        $this->private = $private;
        $this->usesPrivateKeyAgent = $usesPrivateKeyAgent;
    }

    public static function forPrivateKeyAgent(EngineBlock_X509_Certificate $certificate): self
    {
        return new self($certificate, null, true);
    }

    public function getCertificate()
    {
        return $this->certificate;
    }

    /**
     * @return EngineBlock_X509_PrivateKey|null Always null for a private key agent key pair
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
