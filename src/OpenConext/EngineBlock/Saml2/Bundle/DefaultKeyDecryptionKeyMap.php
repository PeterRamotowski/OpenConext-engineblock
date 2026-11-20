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

use OpenConext\EngineBlock\Metadata\X509\EncryptionKeysConfiguration;
use Surfnet\SamlBundle\PrivateKeyAgent\AgentOperation;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;

/**
 * Limits agent decryption candidates to the certificate of the "default" key.
 *
 * The bundle's AgentAssertionDecrypter tries every agent key with "decrypt" in its KeyMap; this map holds at most
 * the default key, so neither another key ID nor a certificate named in an EncryptedKey widens the scope. The
 * bundle's process-wide key name resolver is unaffected. Construction reads the certificate, so build it lazily.
 */
final class DefaultKeyDecryptionKeyMap
{
    public static function create(array $encryptionKeys): KeyMap
    {
        $default = EncryptionKeysConfiguration::fromArray($encryptionKeys, false)->getDefault();
        if (!$default->usesPrivateKeyAgent() || !$default->mayDecrypt()) {
            return new KeyMap([], []);
        }

        return new KeyMap(
            [
                (string) $default->agentKeyName => [
                    'certificate_file' => $default->publicFile,
                    'operations' => [AgentOperation::DECRYPT],
                ],
            ],
            []
        );
    }
}
