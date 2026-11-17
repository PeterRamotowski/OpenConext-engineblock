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

use OpenConext\EngineBlock\Metadata\X509\ConfiguredKey;
use OpenConext\EngineBlock\Metadata\X509\EncryptionKeysConfiguration;
use OpenConext\EngineBlock\Metadata\X509\InvalidEncryptionKeyConfigurationException;

/**
 * Derives the surfnet_saml bundle configuration from EngineBlock's encryption_keys and private_key_agent parameters.
 *
 * The bundle's hosted identity provider and metadata mirror EngineBlock's "default" key. Agent keys are mapped into
 * surfnet_saml.private_key_agent.keys; the HTTP client, token provider, backends and algorithm registration remain
 * the bundle's. Without agent keys the agent stays disabled and nothing changes for local keys.
 */
final class SamlBundleConfiguration
{
    /**
     * The global agent settings EngineBlock passes through unchanged; the bundle validates their values.
     */
    private const array AGENT_SETTINGS = ['base_url', 'allow_insecure_http', 'timeout', 'max_duration', 'algorithms'];

    /**
     * @param array<string, mixed> $agentSettings The private_key_agent parameter
     * @return array<string, mixed> The surfnet_saml extension configuration
     * @throws InvalidEncryptionKeyConfigurationException
     */
    public static function build(EncryptionKeysConfiguration $keys, array $agentSettings): array
    {
        $unknown = array_diff(array_map('strval', array_keys($agentSettings)), self::AGENT_SETTINGS);
        if ($unknown !== []) {
            throw new InvalidEncryptionKeyConfigurationException(
                sprintf('The "private_key_agent" parameter contains unknown settings: %s', implode(', ', $unknown))
            );
        }

        $identity = self::hostedIdentity($keys->getDefault());

        return [
            'hosted' => [
                'metadata' => ['entity_id_route' => 'metadata_idp'] + $identity,
                'identity_provider' => [
                    'enabled' => true,
                    'service_provider_repository' => ServiceProviderRepositoryAdapter::class,
                    'sso_route' => 'authentication_idp_sso',
                ] + $identity,
            ],
            'private_key_agent' => $keys->usesPrivateKeyAgent()
                ? ['enabled' => true, 'keys' => self::agentKeys($keys)] + $agentSettings
                : ['enabled' => false],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function hostedIdentity(ConfiguredKey $key): array
    {
        if ($key->usesPrivateKeyAgent()) {
            // The bundle reads private_key unconditionally and treats an empty value as not configured.
            return ['public_key' => $key->publicFile, 'private_key' => null, 'use_private_key_agent' => true];
        }

        return ['public_key' => $key->publicFile, 'private_key' => $key->privateFile];
    }

    /**
     * @return array<string, array{certificate_file: string, token: string, operations: list<string>}>
     */
    private static function agentKeys(EncryptionKeysConfiguration $keys): array
    {
        $agentKeys = [];
        foreach ($keys->all() as $key) {
            if (!$key->usesPrivateKeyAgent()) {
                continue;
            }

            $operations = array_merge($agentKeys[$key->agentKeyName]['operations'] ?? [], $key->agentOperations);
            $agentKeys[$key->agentKeyName] = [
                'certificate_file' => $key->publicFile,
                'token' => (string) $key->agentToken(),
                'operations' => array_values(array_unique($operations)),
            ];
        }

        return $agentKeys;
    }
}
