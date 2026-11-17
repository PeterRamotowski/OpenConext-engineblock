<?php declare(strict_types=1);

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

namespace OpenConext\EngineBlock\Metadata\X509;

use OpenConext\EngineBlock\Assert\Assertion;
use OpenConext\EngineBlock\Exception\RuntimeException;
use OpenConext\EngineBlockBundle\Exception\UnknownKeyIdException;

class KeyPairFactory implements KeyPairFactoryInterface
{
    const DEFAULT_KEY_PAIR_IDENTIFIER = EncryptionKeysConfiguration::DEFAULT_KEY_ID;

    private EncryptionKeysConfiguration $keyPairConfiguration;

    /**
     * @throws InvalidEncryptionKeyConfigurationException
     */
    public function __construct(array $keyPairConfiguration)
    {
        $this->keyPairConfiguration = EncryptionKeysConfiguration::fromArray($keyPairConfiguration, false);
    }

    /**
     * An agent key pair carries only its certificate: no local private-key object is constructed for it.
     *
     * @throws RuntimeException
     * @throws UnknownKeyIdException
     */
    public function buildFromIdentifier(?string $identifier): X509KeyPair
    {
        if ($identifier === null) {
            $identifier = self::DEFAULT_KEY_PAIR_IDENTIFIER;
        }
        Assertion::nonEmptyString($identifier, 'identifier');

        $key = $this->keyPairConfiguration->get($identifier);
        $certificate = new X509Certificate(
            openssl_x509_read(file_get_contents($key->publicFile)),
            $key->publicFile
        );

        if ($key->usesPrivateKeyAgent()) {
            return X509KeyPair::forPrivateKeyAgent($certificate);
        }

        return new X509KeyPair($certificate, new X509PrivateKey((string) $key->privateFile));
    }

    /**
     * @return array<X509KeyPair>
     *
     * @throws RuntimeException
     */
    public function buildAll(): array
    {
        $pairs = [];

        foreach (array_keys($this->keyPairConfiguration->all()) as $keyId) {
            $pairs[] = $this->buildFromIdentifier((string)$keyId);
        }

        return $pairs;
    }
}
