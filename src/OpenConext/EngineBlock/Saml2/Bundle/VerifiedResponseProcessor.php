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
use SimpleSAML\SAML2\XML\samlp\Response;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\SAML2\Response\ResponseProcessor;

/**
 * Adds a verified envelope and signature methods to the assertion returned by the bundle.
 *
 * The pinned bundle returns only the assertion. It needs the original Response to establish outer
 * signature coverage, while EngineBlock needs the verified envelope for request correlation.
 */
final class VerifiedResponseProcessor
{
    public function __construct(
        private readonly ResponseProcessor $responseProcessor,
        private readonly ResponseEnvelopeVerifier $envelopeVerifier,
        private readonly PolicyCheckingAssertionDecrypter $assertionDecrypter,
        private readonly SignatureAlgorithmPolicy $signaturePolicy,
    ) {
    }

    public function process(
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
        string $destination,
        Response $response,
    ): VerifiedResponse {
        $this->assertionDecrypter->reset();
        try {
            $responseMethod = $response->getSignature()?->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue();
            $verifiedEnvelope = $responseMethod === null ? null : $this->verifyResponseEnvelope($response, $identityProvider);

            $originalAssertion = ($verifiedEnvelope ?? $response)->getAssertions()[0] ?? null;
            $assertionMethod = $originalAssertion instanceof Assertion
                ? $originalAssertion->getSignature()?->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue()
                : null;
            $this->signaturePolicy->assertAllowed($assertionMethod);

            $assertion = $this->responseProcessor->process($serviceProvider, $identityProvider, $destination, $response);

            return new VerifiedResponse(
                $verifiedEnvelope,
                $assertion,
                $responseMethod,
                $assertionMethod ?? $this->assertionDecrypter->getSignatureMethod()
            );
        } finally {
            $this->assertionDecrypter->reset();
        }
    }

    public function verifyResponseEnvelope(Response $response, IdentityProvider $identityProvider): Response
    {
        return $this->envelopeVerifier->verify($response, $identityProvider);
    }
}
