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

use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\X509;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PublicKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Entity\IdentityProvider;

/**
 * The public keys an identity provider signs with, selected as the bundle's ResponseProcessor does:
 * configured keys, then certificate data, then the certificate file.
 */
final class IdentityProviderSigningKeys
{
    /**
     * @return array<int|string, PublicKey>
     */
    public static function forIdentityProvider(IdentityProvider $identityProvider): array
    {
        $certificateFile = $identityProvider->getCertificateFile();
        if ($identityProvider->getKeys() === null
            && $identityProvider->getCertificateData() === null
            && $certificateFile !== null
        ) {
            // saml2 7.0.0-rc4 cannot load PEM certificate files, so the file is read here.
            return [X509Certificate::fromFile($certificateFile)->getPublicKey()];
        }

        $publicKeys = [];
        foreach (KeyLoader::extractPublicKeys($identityProvider) as $index => $key) {
            if ($key instanceof X509) {
                $publicKeys[$index] = (new X509Certificate(PEM::fromString($key->getCertificate())))->getPublicKey();
            }
        }

        return $publicKeys;
    }
}
