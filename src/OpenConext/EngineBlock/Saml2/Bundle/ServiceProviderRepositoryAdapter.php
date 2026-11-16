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

use OpenConext\EngineBlock\Metadata\Entity\ServiceProvider as EngineBlockServiceProvider;
use OpenConext\EngineBlock\Metadata\MetadataRepository\MetadataRepositoryInterface;
use OpenConext\EngineBlock\Metadata\X509\X509Certificate;
use OpenConext\EngineBlock\Metadata\X509\X509CertificateLazyProxy;
use SimpleSAML\SAML2\Certificate\Key;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;

/**
 * Exposes EngineBlock's dynamic SP metadata to the bundle's incoming request bindings.
 *
 * Every configured SP certificate becomes a signing-only key, so the bundle verifies AuthnRequest
 * signatures against the same certificates (including rollover certificates) as EngineBlock.
 */
final class ServiceProviderRepositoryAdapter implements ServiceProviderRepository
{
    public function __construct(private readonly MetadataRepositoryInterface $metadataRepository)
    {
    }

    public function getServiceProvider(string $entityId): ServiceProvider
    {
        $serviceProvider = $this->metadataRepository->findServiceProviderByEntityId($entityId);
        if (!$serviceProvider instanceof EngineBlockServiceProvider) {
            throw new UnknownServiceProviderException($entityId);
        }

        return new ServiceProvider([
            'entityId' => $entityId,
            'keys' => array_map(
                // Metadata pushed from Manage holds lazy proxies that forward toCertData() via __call.
                static fn (X509Certificate|X509CertificateLazyProxy $certificate): array => [
                    'type' => 'X509Certificate',
                    'X509Certificate' => $certificate->toCertData(),
                    Key::USAGE_SIGNING => true,
                    Key::USAGE_ENCRYPTION => false,
                ],
                array_values($serviceProvider->certificates),
            ),
        ]);
    }

    public function hasServiceProvider(string $entityId): bool
    {
        return $this->metadataRepository->findServiceProviderByEntityId($entityId) instanceof EngineBlockServiceProvider;
    }
}
