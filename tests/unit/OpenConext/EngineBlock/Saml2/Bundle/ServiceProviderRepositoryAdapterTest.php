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

use OpenConext\EngineBlock\Metadata\Entity\IdentityProvider;
use OpenConext\EngineBlock\Metadata\Entity\ServiceProvider;
use OpenConext\EngineBlock\Metadata\MetadataRepository\InMemoryMetadataRepository;
use OpenConext\EngineBlock\Metadata\X509\X509CertificateFactory;
use OpenConext\EngineBlock\Metadata\X509\X509CertificateLazyProxy;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\Certificate\Key;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\X509;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;

class ServiceProviderRepositoryAdapterTest extends TestCase
{
    private const SP_ENTITY_ID = 'https://sp.example.edu/metadata';
    private const IDP_ENTITY_ID = 'https://idp.example.edu/metadata';

    #[Test]
    public function every_sp_certificate_is_offered_as_a_signing_key_only(): void
    {
        $current = GeneratedKeyPair::named('sp-current')->certificateData();
        $rollover = GeneratedKeyPair::named('sp-rollover')->certificateData();
        $adapter = $this->adapterFor(new ServiceProvider(self::SP_ENTITY_ID, certificates: [
            'current' => (new X509CertificateFactory())->fromCertData($current),
            'rollover' => (new X509CertificateFactory())->fromCertData($rollover),
        ]));

        $serviceProvider = $adapter->getServiceProvider(self::SP_ENTITY_ID);

        $this->assertSame(self::SP_ENTITY_ID, $serviceProvider->getEntityId());
        $signingKeys = KeyLoader::extractPublicKeys($serviceProvider, Key::USAGE_SIGNING);
        $this->assertSame(
            [$current, $rollover],
            array_map(static fn (X509 $key): string => $key['X509Certificate'], iterator_to_array($signingKeys)),
        );
        $this->assertCount(0, KeyLoader::extractPublicKeys($serviceProvider, Key::USAGE_ENCRYPTION));
    }

    #[Test]
    public function certificates_imported_from_manage_are_offered_as_signing_keys(): void
    {
        $current = GeneratedKeyPair::named('sp-current')->certificateData();
        $rollover = GeneratedKeyPair::named('sp-rollover')->certificateData();
        $adapter = $this->adapterFor(new ServiceProvider(self::SP_ENTITY_ID, certificates: [
            new X509CertificateLazyProxy(new X509CertificateFactory(), $current),
            new X509CertificateLazyProxy(new X509CertificateFactory(), $rollover),
        ]));

        $signingKeys = KeyLoader::extractPublicKeys(
            $adapter->getServiceProvider(self::SP_ENTITY_ID),
            Key::USAGE_SIGNING,
        );

        $this->assertSame(
            [$current, $rollover],
            array_map(static fn (X509 $key): string => $key['X509Certificate'], iterator_to_array($signingKeys)),
        );
    }

    #[Test]
    public function an_sp_without_certificates_offers_no_keys(): void
    {
        $adapter = $this->adapterFor(new ServiceProvider(self::SP_ENTITY_ID));

        $serviceProvider = $adapter->getServiceProvider(self::SP_ENTITY_ID);

        $this->assertCount(0, KeyLoader::extractPublicKeys($serviceProvider));
    }

    #[Test]
    public function only_known_service_providers_are_exposed(): void
    {
        $adapter = $this->adapterFor(new ServiceProvider(self::SP_ENTITY_ID));

        $this->assertTrue($adapter->hasServiceProvider(self::SP_ENTITY_ID));
        $this->assertFalse($adapter->hasServiceProvider(self::IDP_ENTITY_ID));
        $this->assertFalse($adapter->hasServiceProvider('https://unknown.example.edu/metadata'));

        $this->expectException(UnknownServiceProviderException::class);
        $adapter->getServiceProvider(self::IDP_ENTITY_ID);
    }

    private function adapterFor(ServiceProvider $serviceProvider): ServiceProviderRepositoryAdapter
    {
        return new ServiceProviderRepositoryAdapter(new InMemoryMetadataRepository(
            [new IdentityProvider(self::IDP_ENTITY_ID)],
            [$serviceProvider],
        ));
    }
}
