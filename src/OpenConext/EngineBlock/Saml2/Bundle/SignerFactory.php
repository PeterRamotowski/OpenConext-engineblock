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

use OpenConext\EngineBlock\Exception\RuntimeException;
use OpenConext\EngineBlock\Saml2\Bundle\Exception\UnsupportedSignatureAlgorithmException;
use SensitiveParameter;
use SimpleSAML\XMLSecurity\Alg\Signature\PrivateKeyAgentRSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Exception\BlacklistedAlgorithmException;
use SimpleSAML\XMLSecurity\Key\KeyInterface;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use TypeError;

/**
 * RSA-SHA256/384/512 signers for EngineBlock's hosted identities.
 *
 * The bundle's Signers only produce RSA-SHA256, so this factory builds the signer through xml-security's
 * public factory. The bundle's registered agent factories route a certificate key to the private key agent
 * and a private key to OpenSSL; an agent identity therefore never falls back to a local key.
 */
final class SignerFactory
{
    /**
     * @throws UnsupportedSignatureAlgorithmException
     */
    public function forLocalKey(
        #[SensitiveParameter]
        PrivateKey $privateKey,
        string $algorithm = C::SIG_RSA_SHA256,
    ): SignatureAlgorithmInterface {
        return $this->create($algorithm, $privateKey);
    }

    /**
     * @throws UnsupportedSignatureAlgorithmException
     * @throws RuntimeException when no private key agent is registered for the algorithm
     */
    public function forAgentCertificate(
        X509Certificate $certificate,
        string $algorithm = C::SIG_RSA_SHA256,
    ): PrivateKeyAgentRSA {
        try {
            $signer = $this->create($algorithm, $certificate);
        } catch (TypeError $exception) {
            // The default RSA implementation only accepts key material: no agent wrapper is registered.
            throw $this->agentNotRegistered($algorithm, $exception);
        }

        if (!$signer instanceof PrivateKeyAgentRSA) {
            throw $this->agentNotRegistered($algorithm);
        }

        return $signer;
    }

    private function create(string $algorithm, KeyInterface $key): SignatureAlgorithmInterface
    {
        if (!SignatureAlgorithmPolicy::isRsaSha2($algorithm)) {
            throw UnsupportedSignatureAlgorithmException::forSigning($algorithm);
        }

        try {
            return SignatureAlgorithmPolicy::factory()->getAlgorithm($algorithm, $key);
        } catch (BlacklistedAlgorithmException $exception) {
            throw UnsupportedSignatureAlgorithmException::forSigning($algorithm, $exception);
        }
    }

    private function agentNotRegistered(string $algorithm, ?TypeError $previous = null): RuntimeException
    {
        return new RuntimeException(
            sprintf('The private key agent is not registered for "%s" signatures', $algorithm),
            0,
            $previous
        );
    }
}
