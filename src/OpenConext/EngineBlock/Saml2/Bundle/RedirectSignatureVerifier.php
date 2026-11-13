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
use OpenConext\EngineBlock\Saml2\Bundle\Exception\UnsupportedSignatureAlgorithmException;
use Psr\Log\LoggerInterface;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;

/**
 * Verifies HTTP-Redirect AuthnRequest signatures made with RSA-SHA256/384/512.
 *
 * The bundle's Redirect verifier only accepts RSA-SHA256. This verifier checks the signature over the
 * query bytes exactly as received, as parsed by the bundle; it never re-encodes the query.
 */
final class RedirectSignatureVerifier
{
    /**
     * @param list<string> $forbiddenAlgorithms EngineBlock's forbidden_signature_methods
     */
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly array $forbiddenAlgorithms = [],
    ) {
    }

    public function supports(string $algorithm): bool
    {
        return SignatureAlgorithmPolicy::isRsaSha2($algorithm)
            && !in_array($algorithm, $this->forbiddenAlgorithms, true)
            && !SignatureAlgorithmPolicy::isBlacklisted($algorithm);
    }

    /**
     * @param iterable<X509Certificate> $certificates The configured certificates of the service provider
     * @throws UnsupportedSignatureAlgorithmException
     */
    public function isSignedBy(ReceivedAuthnRequestQueryString $query, iterable $certificates): bool
    {
        if (!$query->isSigned()) {
            return false;
        }

        $algorithm = $query->getSignatureAlgorithm();
        if (!$this->supports($algorithm)) {
            throw UnsupportedSignatureAlgorithmException::forVerification($algorithm);
        }

        $payload = $query->getSignedRequestPayload();
        $signature = $query->getDecodedSignature();
        foreach ($certificates as $index => $certificate) {
            try {
                $verifier = SignatureAlgorithmPolicy::factory()->getAlgorithm($algorithm, $certificate->getPublicKey());
                if ($verifier->verify($payload, $signature)) {
                    return true;
                }
            } catch (Exception $exception) {
                $this->logger->debug(sprintf(
                    'Redirect signature verification with certificate #%s failed: %s',
                    $index,
                    $exception->getMessage()
                ));
            }
        }

        return false;
    }
}
