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

use OpenConext\EngineBlock\Metadata\X509\EncryptionKeysConfiguration;
use OpenConext\EngineBlock\Metadata\X509\InvalidEncryptionKeyConfigurationException;
use OpenConext\EngineBlock\Saml2\Bundle\SamlBundleConfiguration;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;

final class OpenConextEngineBlockExtension extends Extension implements PrependExtensionInterface
{
    public function load(array $configs, ContainerBuilder $container): void
    {
    }

    /**
     * Derives the complete surfnet_saml hosted and private_key_agent configuration from the encryption_keys and
     * private_key_agent parameters, so the bundle uses the same identities and backends as EngineBlock.
     * Only the configuration is validated; no key or certificate file is read.
     */
    public function prepend(ContainerBuilder $container): void
    {
        foreach ($container->getExtensionConfig('surfnet_saml') as $config) {
            foreach (['hosted', 'private_key_agent'] as $section) {
                if (is_array($config) && array_key_exists($section, $config)) {
                    throw new InvalidArgumentException(sprintf(
                        'Do not configure surfnet_saml.%s: EngineBlock derives it from the "encryption_keys" and '
                        . '"private_key_agent" parameters',
                        $section
                    ));
                }
            }
        }

        $agentSettings = $container->hasParameter('private_key_agent')
            ? $container->getParameter('private_key_agent') ?? []
            : [];
        if (!is_array($agentSettings)) {
            throw new InvalidArgumentException('The "private_key_agent" parameter must be a mapping');
        }

        $encryptionKeys = $container->getParameter('encryption_keys');
        try {
            $configuration = SamlBundleConfiguration::build(
                EncryptionKeysConfiguration::fromArray($encryptionKeys),
                $agentSettings
            );
        } catch (InvalidEncryptionKeyConfigurationException $exception) {
            throw new InvalidArgumentException($exception->getMessage(), 0, $exception);
        }

        $container->prependExtensionConfig('surfnet_saml', $configuration);
        // Only the bundle's lazy token provider resolves agent tokens; EngineBlock's services read the parameter
        // on every request and must neither resolve nor carry them.
        $container->setParameter('encryption_keys', EncryptionKeysConfiguration::withoutAgentTokens($encryptionKeys));
    }
}
