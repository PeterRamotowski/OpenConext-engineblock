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

namespace OpenConext\EngineBlockBundle\DependencyInjection;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Surfnet\SamlBundle\DependencyInjection\SurfnetSamlExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;

/**
 * The surfnet_saml configuration EngineBlock derives from encryption_keys, loaded by the bundle's own extension.
 */
class OpenConextEngineBlockExtensionTest extends TestCase
{
    private const AGENT_SETTINGS = ['base_url' => 'https://agent.example.org', 'timeout' => 2.0, 'max_duration' => 4.0];

    #[Test]
    public function localKeysKeepTheBundleOnLocalKeysWithTheAgentDisabled(): void
    {
        $container = $this->loadBundle([
            'default' => ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem'],
            'rollover' => ['publicFile' => '/keys/rollover.crt', 'privateFile' => '/keys/rollover.pem'],
        ], self::AGENT_SETTINGS);

        $identityProvider = $container->getDefinition('surfnet_saml.configuration.hosted_entities')->getArgument(3);
        self::assertSame('/keys/default.crt', $identityProvider['public_key']);
        self::assertSame('/keys/default.pem', $identityProvider['private_key']);
        self::assertFalse($container->hasDefinition('surfnet_saml.private_key_agent.key_map'));
        self::assertFalse($container->hasDefinition('surfnet_saml.private_key_agent.validate_command'));
        self::assertSame(
            'surfnet_saml.saml2.local_assertion_decrypter',
            (string) $container->getAlias('surfnet_saml.saml2.assertion_decrypter')
        );
    }

    #[Test]
    public function agentKeysAreMappedIntoTheBundlePrivateKeyAgentConfiguration(): void
    {
        $container = $this->loadBundle([
            'default' => [
                'backend' => 'agent',
                'publicFile' => '/keys/default.crt',
                'agent' => ['key' => 'eb-default', 'token' => 'default-token', 'operations' => ['sign', 'decrypt']],
            ],
            'rollover' => [
                'backend' => 'agent',
                'publicFile' => '/keys/rollover.crt',
                'agent' => ['key' => 'eb-rollover', 'token' => 'rollover-token', 'operations' => ['sign']],
            ],
            'legacy' => ['publicFile' => '/keys/legacy.crt', 'privateFile' => '/keys/legacy.pem'],
        ], self::AGENT_SETTINGS);

        $identityProvider = $container->getDefinition('surfnet_saml.configuration.hosted_entities')->getArgument(3);
        self::assertTrue($identityProvider['use_private_key_agent']);
        self::assertArrayNotHasKey('private_key', $identityProvider);
        self::assertTrue($container->getDefinition('surfnet_saml.configuration.metadata')->getProperties()['usePrivateKeyAgent']);

        $keyMap = $container->getDefinition('surfnet_saml.private_key_agent.key_map');
        self::assertSame(
            [
                'eb-default' => ['certificate_file' => '/keys/default.crt', 'operations' => ['sign', 'decrypt']],
                'eb-rollover' => ['certificate_file' => '/keys/rollover.crt', 'operations' => ['sign']],
            ],
            $keyMap->getArgument(0)
        );
        self::assertSame(
            [
                'surfnet_saml.hosted.identity_provider' => '/keys/default.crt',
                'surfnet_saml.hosted.metadata' => '/keys/default.crt',
            ],
            $keyMap->getArgument(1)
        );
        self::assertSame(
            ['eb-default' => 'default-token', 'eb-rollover' => 'rollover-token'],
            $container->getDefinition('surfnet_saml.private_key_agent.token_provider')->getArgument(0)
        );
        self::assertSame(
            'https://agent.example.org',
            $container->getDefinition('surfnet_saml.private_key_agent.signature_backend')->getArgument(3)
        );
        $httpClientOptions = $container->getDefinition('surfnet_saml.private_key_agent.symfony_http_client')->getArgument(0);
        self::assertSame(2.0, $httpClientOptions['timeout']);
        self::assertSame(4.0, $httpClientOptions['max_duration']);
        self::assertSame(0, $httpClientOptions['max_redirects']);
        self::assertTrue($container->hasDefinition('surfnet_saml.private_key_agent.validate_command'));

        $runtimeKeys = $container->getParameter('encryption_keys');
        self::assertSame(['key' => 'eb-default', 'operations' => ['sign', 'decrypt']], $runtimeKeys['default']['agent']);
        self::assertSame(['key' => 'eb-rollover', 'operations' => ['sign']], $runtimeKeys['rollover']['agent']);
        self::assertSame('/keys/legacy.pem', $runtimeKeys['legacy']['privateFile']);
    }

    #[Test]
    public function aLocalDefaultKeyKeepsTheHostedIdentitiesLocalWhileAnotherKeyUsesTheAgent(): void
    {
        $container = $this->loadBundle([
            'default' => ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem'],
            'rollover' => [
                'backend' => 'agent',
                'publicFile' => '/keys/rollover.crt',
                'agent' => ['key' => 'eb-rollover', 'token' => 'rollover-token', 'operations' => ['sign']],
            ],
        ], self::AGENT_SETTINGS);

        $identityProvider = $container->getDefinition('surfnet_saml.configuration.hosted_entities')->getArgument(3);
        self::assertSame('/keys/default.pem', $identityProvider['private_key']);
        self::assertFalse($identityProvider['use_private_key_agent'] ?? false);
        self::assertSame([], $container->getDefinition('surfnet_saml.private_key_agent.key_map')->getArgument(1));
    }

    #[Test]
    public function aBundleConfigurationNextToTheDerivedOneIsRejected(): void
    {
        $container = $this->container(['default' => ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem']]);
        $container->prependExtensionConfig('surfnet_saml', ['private_key_agent' => ['enabled' => true]]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Do not configure surfnet_saml.private_key_agent');

        (new OpenConextEngineBlockExtension())->prepend($container);
    }

    #[Test]
    public function invalidKeyConfigurationFailsTheContainerBuild(): void
    {
        $container = $this->container([
            'default' => ['backend' => 'agent', 'publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem'],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('encryption_keys.default.privateFile must not be set');

        (new OpenConextEngineBlockExtension())->prepend($container);
    }

    #[Test]
    public function unknownAgentSettingsAreRejected(): void
    {
        $container = $this->container(
            ['default' => ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem']],
            ['base_url' => 'https://agent.example.org', 'retries' => 3]
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown settings: retries');

        (new OpenConextEngineBlockExtension())->prepend($container);
    }

    private function loadBundle(array $encryptionKeys, array $agentSettings): ContainerBuilder
    {
        $container = $this->container($encryptionKeys, $agentSettings);
        $samlExtension = new SurfnetSamlExtension();
        $container->registerExtension($samlExtension);

        (new OpenConextEngineBlockExtension())->prepend($container);
        $samlExtension->load($container->getExtensionConfig('surfnet_saml'), $container);

        return $container;
    }

    private function container(array $encryptionKeys, ?array $agentSettings = null): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('encryption_keys', $encryptionKeys);
        if ($agentSettings !== null) {
            $container->setParameter('private_key_agent', $agentSettings);
        }

        return $container;
    }
}
