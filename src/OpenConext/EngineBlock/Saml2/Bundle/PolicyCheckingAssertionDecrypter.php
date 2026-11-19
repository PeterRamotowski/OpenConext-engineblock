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

use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\SAML2\Response\AssertionDecrypter;

/**
 * Enforces EngineBlock's additional algorithm restrictions after decryption, before the bundle verifies the assertion.
 * Keeps the algorithm available for rollout logging after the processor returns a validated, signature-free assertion.
 */
final class PolicyCheckingAssertionDecrypter implements AssertionDecrypter
{
    private ?string $signatureMethod = null;

    public function __construct(
        private readonly AssertionDecrypter $inner,
        private readonly SignatureAlgorithmPolicy $signaturePolicy,
    ) {
    }

    public function decrypt(
        EncryptedAssertion $encryptedAssertion,
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
    ): Assertion {
        $this->reset();
        $assertion = $this->inner->decrypt($encryptedAssertion, $serviceProvider, $identityProvider);
        $algorithm = $assertion->getSignature()?->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue();
        $this->signaturePolicy->assertAllowed($algorithm);
        $this->signatureMethod = $algorithm;

        return $assertion;
    }

    public function getSignatureMethod(): ?string
    {
        return $this->signatureMethod;
    }

    public function reset(): void
    {
        $this->signatureMethod = null;
    }
}
