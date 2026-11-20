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

namespace OpenConext\EngineBlock\Metadata\X509;

use OpenConext\EngineBlockBundle\Exception\UnknownKeyIdException;

/**
 * The validated encryption_keys parameter: EngineBlock's key pairs by key ID, each with an explicit backend.
 *
 *     encryption_keys:
 *         default:                       # local key (backend: local is the default)
 *             publicFile: /config/engine/engineblock.crt
 *             privateFile: /config/engine/engineblock.pem
 *         rollover:                      # certificate-only key held by the Private Key Agent
 *             backend: agent
 *             publicFile: /config/engine/rollover.crt
 *             agent:
 *                 key: engineblock-rollover
 *                 token: '%env(trim:file:PKA_ROLLOVER_TOKEN_FILE)%'
 *                 operations: [sign]
 *
 * Every key signs, so an agent key must allow "sign". Only the "default" key decrypts received assertions, so only
 * that key may allow "decrypt". Files are never read here.
 *
 * Agent tokens are only needed by the bundle's lazy token provider. The container build therefore removes them
 * from the encryption_keys parameter (see withoutAgentTokens()), so EngineBlock's own consumers never resolve them.
 */
final class EncryptionKeysConfiguration
{
    public const string DEFAULT_KEY_ID = 'default';

    private const array KEY_FIELDS = ['backend', 'publicFile', 'privateFile', 'agent'];
    private const array AGENT_FIELDS = ['key', 'token', 'operations'];
    private const string AGENT_KEY_NAME_PATTERN = '/^[a-zA-Z0-9_-]{1,64}$/';

    /**
     * @param array<string, ConfiguredKey> $keys
     */
    private function __construct(private readonly array $keys)
    {
    }

    /**
     * @param bool $agentTokensRequired False for the compiled encryption_keys parameter, from which tokens are removed
     * @throws InvalidEncryptionKeyConfigurationException
     */
    public static function fromArray(mixed $configuration, bool $agentTokensRequired = true): self
    {
        if (!is_array($configuration) || $configuration === []) {
            throw new InvalidEncryptionKeyConfigurationException('The "encryption_keys" parameter must configure at least one key');
        }

        $keys = [];
        foreach ($configuration as $keyId => $keyConfiguration) {
            $keyId = (string) $keyId;
            if ($keyId === '') {
                throw new InvalidEncryptionKeyConfigurationException('The "encryption_keys" parameter contains an empty key ID');
            }

            $keys[$keyId] = self::parseKey($keyId, $keyConfiguration, $agentTokensRequired);
        }

        if (!isset($keys[self::DEFAULT_KEY_ID])) {
            throw new InvalidEncryptionKeyConfigurationException(
                'The "encryption_keys" parameter must configure a "default" key'
            );
        }

        self::assertConsistentAgentKeys($keys);

        return new self($keys);
    }

    /**
     * The configuration without agent tokens, for the parameter that EngineBlock's own services read.
     *
     * @param array<mixed> $configuration A configuration accepted by fromArray()
     * @return array<mixed>
     */
    public static function withoutAgentTokens(array $configuration): array
    {
        foreach ($configuration as $keyId => $keyConfiguration) {
            if (is_array($keyConfiguration) && is_array($keyConfiguration['agent'] ?? null)) {
                unset($configuration[$keyId]['agent']['token']);
            }
        }

        return $configuration;
    }

    /**
     * @throws UnknownKeyIdException
     */
    public function get(string $keyId): ConfiguredKey
    {
        if (!isset($this->keys[$keyId])) {
            throw new UnknownKeyIdException($keyId);
        }

        return $this->keys[$keyId];
    }

    public function getDefault(): ConfiguredKey
    {
        return $this->keys[self::DEFAULT_KEY_ID];
    }

    /**
     * @return array<string, ConfiguredKey> In configuration order
     */
    public function all(): array
    {
        return $this->keys;
    }

    public function usesPrivateKeyAgent(): bool
    {
        foreach ($this->keys as $key) {
            if ($key->usesPrivateKeyAgent()) {
                return true;
            }
        }

        return false;
    }

    private static function parseKey(string $keyId, mixed $configuration, bool $agentTokensRequired): ConfiguredKey
    {
        $path = sprintf('encryption_keys.%s', $keyId);
        if (!is_array($configuration)) {
            throw new InvalidEncryptionKeyConfigurationException(sprintf('%s must be a mapping', $path));
        }
        self::assertKnownFields($path, $configuration, self::KEY_FIELDS);

        $backend = $configuration['backend'] ?? ConfiguredKey::BACKEND_LOCAL;
        $publicFile = self::requiredString($path . '.publicFile', $configuration['publicFile'] ?? null);

        return match ($backend) {
            ConfiguredKey::BACKEND_LOCAL => self::parseLocalKey($keyId, $path, $publicFile, $configuration),
            ConfiguredKey::BACKEND_AGENT => self::parseAgentKey(
                $keyId,
                $path,
                $publicFile,
                $configuration,
                $agentTokensRequired
            ),
            default => throw new InvalidEncryptionKeyConfigurationException(sprintf(
                '%s.backend must be "%s" or "%s"',
                $path,
                ConfiguredKey::BACKEND_LOCAL,
                ConfiguredKey::BACKEND_AGENT
            )),
        };
    }

    private static function parseLocalKey(string $keyId, string $path, string $publicFile, array $configuration): ConfiguredKey
    {
        if (array_key_exists('agent', $configuration)) {
            throw new InvalidEncryptionKeyConfigurationException(
                sprintf('%s.agent may only be set when %s.backend is "agent"', $path, $path)
            );
        }

        return ConfiguredKey::local(
            $keyId,
            $publicFile,
            self::requiredString($path . '.privateFile', $configuration['privateFile'] ?? null)
        );
    }

    private static function parseAgentKey(
        string $keyId,
        string $path,
        string $publicFile,
        array $configuration,
        bool $tokenRequired
    ): ConfiguredKey {
        // Never configure both, so that an agent failure can never fall back to a local private key.
        if (array_key_exists('privateFile', $configuration)) {
            throw new InvalidEncryptionKeyConfigurationException(
                sprintf('%s.privateFile must not be set when %s.backend is "agent"', $path, $path)
            );
        }

        $agent = $configuration['agent'] ?? null;
        if (!is_array($agent)) {
            throw new InvalidEncryptionKeyConfigurationException(
                sprintf('%s.agent must be set when %s.backend is "agent"', $path, $path)
            );
        }
        self::assertKnownFields($path . '.agent', $agent, self::AGENT_FIELDS);

        $keyName = self::requiredString($path . '.agent.key', $agent['key'] ?? null);
        if (preg_match(self::AGENT_KEY_NAME_PATTERN, $keyName) !== 1) {
            throw new InvalidEncryptionKeyConfigurationException(
                sprintf('%s.agent.key must match [a-zA-Z0-9_-]{1,64}', $path)
            );
        }
        $token = $agent['token'] ?? null;
        if (($tokenRequired || $token !== null) && (!is_string($token) || $token === '')) {
            // The token value is never part of a message.
            throw new InvalidEncryptionKeyConfigurationException(sprintf('%s.agent.token must be set', $path));
        }

        return ConfiguredKey::agent(
            $keyId,
            $publicFile,
            $keyName,
            $token,
            self::parseOperations($keyId, $path . '.agent.operations', $agent['operations'] ?? null)
        );
    }

    /**
     * @return list<string>
     */
    private static function parseOperations(string $keyId, string $path, mixed $operations): array
    {
        if (!is_array($operations) || $operations === []) {
            throw new InvalidEncryptionKeyConfigurationException(sprintf('%s must list at least one operation', $path));
        }

        $parsed = [];
        foreach ($operations as $operation) {
            if (!in_array($operation, [ConfiguredKey::OPERATION_SIGN, ConfiguredKey::OPERATION_DECRYPT], true)) {
                throw new InvalidEncryptionKeyConfigurationException(
                    sprintf('%s may only contain "sign" and "decrypt"', $path)
                );
            }
            $parsed[$operation] = $operation;
        }

        if (!isset($parsed[ConfiguredKey::OPERATION_SIGN])) {
            throw new InvalidEncryptionKeyConfigurationException(
                sprintf('%s must contain "sign": EngineBlock signs with every configured key', $path)
            );
        }

        if (isset($parsed[ConfiguredKey::OPERATION_DECRYPT]) && $keyId !== self::DEFAULT_KEY_ID) {
            throw new InvalidEncryptionKeyConfigurationException(sprintf(
                '%s must not contain "decrypt": only the "%s" key decrypts received assertions',
                $path,
                self::DEFAULT_KEY_ID
            ));
        }

        return array_values($parsed);
    }

    /**
     * Key IDs may share an agent key only when they use the same certificate and token.
     *
     * @param array<string, ConfiguredKey> $keys
     */
    private static function assertConsistentAgentKeys(array $keys): void
    {
        $byName = [];
        foreach ($keys as $key) {
            if (!$key->usesPrivateKeyAgent()) {
                continue;
            }

            $other = $byName[$key->agentKeyName] ?? null;
            if ($other !== null
                && ($other->publicFile !== $key->publicFile || $other->agentToken() !== $key->agentToken())
            ) {
                throw new InvalidEncryptionKeyConfigurationException(sprintf(
                    'encryption_keys.%s and encryption_keys.%s use agent key "%s" with a different publicFile or token',
                    $other->keyId,
                    $key->keyId,
                    $key->agentKeyName
                ));
            }
            $byName[$key->agentKeyName] = $other ?? $key;
        }
    }

    /**
     * @param array<mixed> $configuration
     * @param list<string> $knownFields
     */
    private static function assertKnownFields(string $path, array $configuration, array $knownFields): void
    {
        $unknown = array_diff(array_map('strval', array_keys($configuration)), $knownFields);
        if ($unknown !== []) {
            throw new InvalidEncryptionKeyConfigurationException(
                sprintf('%s contains unknown fields: %s', $path, implode(', ', $unknown))
            );
        }
    }

    private static function requiredString(string $path, mixed $value): string
    {
        if (!is_string($value) || $value === '') {
            throw new InvalidEncryptionKeyConfigurationException(sprintf('%s must be set', $path));
        }

        return $value;
    }
}
