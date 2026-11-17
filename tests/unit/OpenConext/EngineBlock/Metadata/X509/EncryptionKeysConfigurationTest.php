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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class EncryptionKeysConfigurationTest extends TestCase
{
    private const TOKEN = 'secret-agent-token';

    #[Test]
    public function keysWithoutABackendStayLocal(): void
    {
        $keys = EncryptionKeysConfiguration::fromArray([
            'default' => ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem'],
        ]);

        self::assertFalse($keys->usesPrivateKeyAgent());
        self::assertSame('/keys/default.pem', $keys->getDefault()->privateFile);
    }

    #[Test]
    public function anAgentKeyIsCertificateOnly(): void
    {
        $keys = EncryptionKeysConfiguration::fromArray([
            'default' => ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem'],
            'rollover' => self::agentKey('eb-rollover', ['sign']),
        ]);

        $rollover = $keys->get('rollover');
        self::assertTrue($keys->usesPrivateKeyAgent());
        self::assertTrue($rollover->usesPrivateKeyAgent());
        self::assertNull($rollover->privateFile);
        self::assertSame('eb-rollover', $rollover->agentKeyName);
        self::assertSame(['sign'], $rollover->agentOperations);
    }

    #[Test]
    public function theCompiledParameterWithoutTokensIsAccepted(): void
    {
        $configuration = ['default' => self::agentKey('eb', ['sign', 'decrypt'])];
        $compiled = EncryptionKeysConfiguration::withoutAgentTokens($configuration);

        $default = EncryptionKeysConfiguration::fromArray($compiled, false)->getDefault();

        self::assertArrayNotHasKey('token', $compiled['default']['agent']);
        self::assertNull($default->agentToken());
        self::assertSame('eb', $default->agentKeyName);
    }

    #[Test]
    #[DataProvider('invalidConfigurations')]
    public function invalidConfigurationsAreRejectedWithoutRevealingTokens(array $configuration, string $message): void
    {
        try {
            EncryptionKeysConfiguration::fromArray($configuration);
            self::fail('The configuration must be rejected');
        } catch (InvalidEncryptionKeyConfigurationException $exception) {
            self::assertStringContainsString($message, $exception->getMessage());
            self::assertStringNotContainsString(self::TOKEN, $exception->getMessage());
        }
    }

    public static function invalidConfigurations(): array
    {
        $local = ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem'];

        return [
            'no default key' => [['rollover' => $local], 'must configure a "default" key'],
            'local key without privateFile' => [
                ['default' => ['publicFile' => '/keys/default.crt']],
                'encryption_keys.default.privateFile must be set',
            ],
            'key without publicFile' => [
                ['default' => ['privateFile' => '/keys/default.pem']],
                'encryption_keys.default.publicFile must be set',
            ],
            'agent key with privateFile' => [
                ['default' => self::agentKey('eb', ['sign']) + ['privateFile' => '/keys/default.pem']],
                'encryption_keys.default.privateFile must not be set when encryption_keys.default.backend is "agent"',
            ],
            'local key with agent settings' => [
                ['default' => $local + ['agent' => ['key' => 'eb']]],
                'encryption_keys.default.agent may only be set',
            ],
            'unknown backend' => [
                ['default' => $local + ['backend' => 'hsm']],
                'encryption_keys.default.backend must be "local" or "agent"',
            ],
            'misspelled field' => [
                ['default' => $local + ['privatefile' => '/keys/default.pem']],
                'encryption_keys.default contains unknown fields: privatefile',
            ],
            'agent key without agent settings' => [
                ['default' => ['backend' => 'agent', 'publicFile' => '/keys/default.crt']],
                'encryption_keys.default.agent must be set',
            ],
            'agent key without token' => [
                ['default' => ['backend' => 'agent', 'publicFile' => '/keys/default.crt', 'agent' => ['key' => 'eb', 'operations' => ['sign']]]],
                'encryption_keys.default.agent.token must be set',
            ],
            'invalid agent key name' => [
                ['default' => self::agentKey('eb/default', ['sign'])],
                'encryption_keys.default.agent.key must match',
            ],
            'unknown operation' => [
                ['default' => self::agentKey('eb', ['sign', 'unwrap'])],
                'may only contain "sign" and "decrypt"',
            ],
            'agent key that cannot sign' => [
                ['default' => self::agentKey('eb', ['decrypt'])],
                'must contain "sign"',
            ],
            'decryption with a non-default key' => [
                ['default' => $local, 'rollover' => self::agentKey('eb-rollover', ['sign', 'decrypt'])],
                'encryption_keys.rollover.agent.operations must not contain "decrypt"',
            ],
            'one agent key name for different certificates' => [
                [
                    'default' => self::agentKey('eb', ['sign']),
                    'rollover' => ['publicFile' => '/keys/other.crt'] + self::agentKey('eb', ['sign']),
                ],
                'use agent key "eb" with a different publicFile or token',
            ],
        ];
    }

    private static function agentKey(string $name, array $operations): array
    {
        return [
            'backend' => 'agent',
            'publicFile' => '/keys/default.crt',
            'agent' => ['key' => $name, 'token' => self::TOKEN, 'operations' => $operations],
        ];
    }
}
