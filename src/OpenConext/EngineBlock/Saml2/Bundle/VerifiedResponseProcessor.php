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

use SimpleSAML\SAML2\XML\samlp\Response;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\SAML2\Response\ResponseProcessor;

/**
 * Runs the bundle's ResponseProcessor and adds the separately verified Response envelope.
 *
 * The bundle's processor only returns the Assertion. Assertion validation, decryption and private key agent
 * calls stay in the processor; this adapter only verifies the outer signature a second time.
 */
final class VerifiedResponseProcessor
{
    public function __construct(
        private readonly ResponseProcessor $responseProcessor,
        private readonly ResponseEnvelopeVerifier $envelopeVerifier,
    ) {
    }

    public function process(
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
        string $destination,
        Response $response,
    ): VerifiedResponse {
        $verifiedEnvelope = $response->isSigned()
            ? $this->envelopeVerifier->verify($response, $identityProvider)
            : null;

        // The verified copy has lost its signature; the processor needs the original to see that it was signed.
        $assertion = $this->responseProcessor->process($serviceProvider, $identityProvider, $destination, $response);

        return new VerifiedResponse($verifiedEnvelope, $assertion);
    }
}
