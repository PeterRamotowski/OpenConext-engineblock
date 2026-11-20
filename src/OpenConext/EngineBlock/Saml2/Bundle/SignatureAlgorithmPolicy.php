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

use OpenConext\EngineBlock\Saml2\Bundle\Exception\UnsupportedSignatureAlgorithmException;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C;

/**
 * Signature algorithm policy shared by the EngineBlock adapters around the Stepup SAML bundle.
 *
 * Every factory honours the blacklist the bundle installs in the saml2 container, so EngineBlock can
 * narrow the accepted algorithms but never accept one the bundle rejects.
 */
final class SignatureAlgorithmPolicy
{
    public const RSA_SHA2 = [
        C::SIG_RSA_SHA256,
        C::SIG_RSA_SHA384,
        C::SIG_RSA_SHA512,
    ];

    /** @param list<string> $forbiddenAlgorithms */
    public function __construct(private readonly array $forbiddenAlgorithms)
    {
    }

    public function assertAllowed(?string $algorithm): void
    {
        if ($algorithm !== null && $this->isForbidden($algorithm)) {
            throw UnsupportedSignatureAlgorithmException::forVerification($algorithm);
        }
    }

    public function supportsXmlVerification(string $algorithm): bool
    {
        return in_array($algorithm, RSA::getSupportedAlgorithms(), true) && $this->isAllowed($algorithm);
    }

    public function supportsRedirectVerification(string $algorithm): bool
    {
        return self::isRsaSha2($algorithm) && $this->isAllowed($algorithm);
    }

    private function isAllowed(string $algorithm): bool
    {
        return !$this->isForbidden($algorithm) && !self::isBlacklisted($algorithm);
    }

    private function isForbidden(string $algorithm): bool
    {
        return in_array($algorithm, $this->forbiddenAlgorithms, true);
    }

    public static function factory(): SignatureAlgorithmFactory
    {
        return new SignatureAlgorithmFactory(self::blacklist());
    }

    /**
     * @return list<string>
     */
    public static function blacklist(): array
    {
        return array_values(
            ContainerSingleton::getInstance()->getBlacklistedEncryptionAlgorithms()
                ?? SignatureAlgorithmFactory::DEFAULT_BLACKLIST
        );
    }

    public static function isBlacklisted(string $algorithm): bool
    {
        return in_array($algorithm, self::blacklist(), true);
    }

    public static function isRsaSha2(string $algorithm): bool
    {
        return in_array($algorithm, self::RSA_SHA2, true);
    }
}
