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

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;

final class OpenConextEngineBlockExtension extends Extension implements PrependExtensionInterface
{
    public const DEFAULT_PUBLIC_KEY_FILE = 'engineblock.saml_bundle.default_public_key_file';
    public const DEFAULT_PRIVATE_KEY_FILE = 'engineblock.saml_bundle.default_private_key_file';

    public function load(array $configs, ContainerBuilder $container): void
    {
    }

    /**
     * Exposes the files of the "default" encryption key as scalar parameters before the bundle configuration
     * is resolved, so the surfnet_saml hosted entities use the same identity as EngineBlock.
     */
    public function prepend(ContainerBuilder $container): void
    {
        $defaultKey = $container->getParameter('encryption_keys')['default'] ?? null;
        if (!is_array($defaultKey) || !isset($defaultKey['publicFile'], $defaultKey['privateFile'])) {
            throw new InvalidArgumentException(
                'The "encryption_keys" parameter must configure a "default" key with a publicFile and privateFile'
            );
        }

        $container->setParameter(self::DEFAULT_PUBLIC_KEY_FILE, $defaultKey['publicFile']);
        $container->setParameter(self::DEFAULT_PRIVATE_KEY_FILE, $defaultKey['privateFile']);
    }
}
