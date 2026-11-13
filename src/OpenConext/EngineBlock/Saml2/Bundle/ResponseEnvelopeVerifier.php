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

use Exception;
use Psr\Log\LoggerInterface;
use SimpleSAML\SAML2\Response\Exception\InvalidSignatureException;
use SimpleSAML\SAML2\XML\samlp\Response;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\Signing\SignatureTransformGuard;

/**
 * Verifies the signature of a Response envelope and returns the Response as covered by that signature.
 *
 * Applies the same trust and algorithm policy as the bundle's ResponseProcessor: the identity provider's
 * configured certificates (keys, then certificate data, then certificate file), the transform guard and
 * any non-blacklisted RSA algorithm. The returned copy no longer carries the signature.
 */
final class ResponseEnvelopeVerifier
{
    public function __construct(private readonly LoggerInterface $logger)
    {
    }

    /**
     * @throws InvalidSignatureException when the Response is unsigned or no configured certificate verifies it
     * @throws SignatureValidationFailedException when the signature uses a forbidden transform
     */
    public function verify(Response $response, IdentityProvider $identityProvider): Response
    {
        $signature = $response->getSignature();
        if ($signature === null) {
            throw new InvalidSignatureException('The Response is not signed');
        }

        SignatureTransformGuard::assertNoForbiddenTransforms($signature->toXML());
        $algorithm = $signature->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue();

        $lastException = null;
        foreach (IdentityProviderSigningKeys::forIdentityProvider($identityProvider) as $index => $publicKey) {
            try {
                $verified = $response->verify(SignatureAlgorithmPolicy::forXmlVerification($algorithm, $publicKey));
                if ($verified instanceof Response) {
                    return $verified;
                }
            } catch (Exception $exception) {
                $this->logger->debug(sprintf(
                    'Response signature verification with key #%s failed: %s',
                    $index,
                    $exception->getMessage()
                ));
                $lastException = $exception;
            }
        }

        throw new InvalidSignatureException(
            'The Response signature could not be verified with any configured certificate of the identity provider',
            0,
            $lastException
        );
    }
}
