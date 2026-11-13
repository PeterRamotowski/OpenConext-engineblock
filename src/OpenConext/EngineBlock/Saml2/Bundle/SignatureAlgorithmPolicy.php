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

use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Exception\UnsupportedAlgorithmException;
use SimpleSAML\XMLSecurity\Key\PublicKey;

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

    /**
     * The policy the bundle applies to XML signatures: any RSA algorithm that is not blacklisted.
     *
     * @throws UnsupportedAlgorithmException
     */
    public static function forXmlVerification(string $algorithm, PublicKey $key): SignatureAlgorithmInterface
    {
        if (!in_array($algorithm, RSA::getSupportedAlgorithms(), true)) {
            throw new UnsupportedAlgorithmException(sprintf('Unsupported RSA signature algorithm "%s"', $algorithm));
        }

        return self::factory()->getAlgorithm($algorithm, $key);
    }
}
