<?php

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

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use OpenConext\EngineBlock\Metadata\Loa;
use OpenConext\EngineBlock\Stepup\StepupGsspUserAttributeExtension;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Extensions;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;

class EngineBlock_Test_Saml2_AuthnRequestAnnotationDecoratorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private const LOA_2 = 'http://vm.openconext.org/assurance/loa2';
    private const LOA_3 = 'http://vm.openconext.org/assurance/loa3';

    public function testToString()
    {
        $annotatedRequest = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['id' => 'TEST123']);
        $annotatedRequest->setDebug();

        $dump = json_decode($annotatedRequest->__toString(), true);

        $this->assertStringContainsString('ID="TEST123"', $dump['sspMessage']);
        $this->assertStringContainsString('IssueInstant="1970-01-01T00:00:00Z"', $dump['sspMessage']);
        $this->assertTrue($dump['debug']);
        $this->assertFalse($dump['wasSigned']);
        $this->assertNull($dump['keyId']);
        $this->assertArrayNotHasKey('stale', $dump);
    }

    public function test_retrieve_loa_obligations_no_loa()
    {
        $annotatedRequest = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest();
        $this->assertEmpty($annotatedRequest->getStepupObligations([]));
    }

    public function test_retrieve_loa_obligations_one_match()
    {
        $loa = Mockery::mock(Loa::class);
        $loa->shouldReceive('getIdentifier')->andReturn(self::LOA_2)->once();

        $annotatedRequest = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['classRefs' => [self::LOA_2]]);
        $obligations = $annotatedRequest->getStepupObligations([$loa]);
        $this->assertTrue(is_array($obligations));
        $this->assertCount(1, $obligations);
        $this->assertEquals(reset($obligations), $loa);
    }

    public function test_retrieve_loa_obligations_multiple_matches()
    {
        $loa2 = Mockery::mock(Loa::class);
        $loa2->shouldReceive('getIdentifier')->andReturn(self::LOA_2)->twice();
        $loa3 = Mockery::mock(Loa::class);
        $loa3->shouldReceive('getIdentifier')->andReturn(self::LOA_3)->twice();

        $annotatedRequest = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest([
            'classRefs' => [self::LOA_2, self::LOA_3],
        ]);
        $obligations = $annotatedRequest->getStepupObligations([$loa2, $loa3]);
        $this->assertTrue(is_array($obligations));
        $this->assertCount(2, $obligations);
    }

    public function test_relaystate_persists_through_serialization()
    {
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['id' => 'RS1'], 'ss:mem:relay-123');

        $restored = unserialize(serialize($decorator));

        $this->assertEquals('ss:mem:relay-123', $restored->getRelayState(), 'RelayState should survive serialization');
        $this->assertStringNotContainsString('ss:mem:relay-123', $restored->toXml());
    }

    public function test_annotations_and_message_survive_serialization()
    {
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest([
            'id' => '_link',
            'issuer' => 'https://sp.example.org',
            'acsUrl' => 'https://sp.example.org/acs',
            'classRefs' => [self::LOA_2],
        ]);
        $decorator->setKeyId('20260101');
        $decorator->setWasSigned();
        $decorator->setTransparent();
        $decorator->setDeliverByBinding('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
        $decorator->setIDPList(['https://idp.example.org']);
        $decorator->setProxyCount(2);

        /** @var EngineBlock_Saml2_AuthnRequestAnnotationDecorator $restored */
        $restored = unserialize(serialize($decorator));
        $restored->assertRestored();

        $this->assertSame(AuthnRequest::class, get_class($restored->getSspMessage()));
        $this->assertSame('_link', $restored->getId());
        $this->assertSame('https://sp.example.org', $restored->getIssuerValue());
        $this->assertSame('https://sp.example.org/acs', $restored->getAssertionConsumerServiceURL());
        $this->assertSame(['AuthnContextClassRef' => [self::LOA_2], 'Comparison' => 'exact'], $restored->getRequestedAuthnContext());
        $this->assertSame('20260101', $restored->getKeyId());
        $this->assertTrue($restored->wasSigned());
        $this->assertTrue($restored->isTransparent());
        $this->assertSame('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', $restored->getDeliverByBinding());
        $this->assertSame(['https://idp.example.org'], $restored->getIDPList());
        $this->assertSame(2, $restored->getProxyCount());
    }

    public function test_extensions_are_preserved_when_the_gssp_user_attributes_are_added()
    {
        $custom = DOMDocumentFactory::fromString('<x:Custom xmlns:x="urn:example:custom">keep</x:Custom>')->documentElement;
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest();
        $decorator->setExtensions(new Extensions([new Chunk($custom)]));

        $assertion = EngineBlock_Test_Saml2_MessageFixtures::assertion([
            'attributes' => ['urn:mace:dir:attribute-def:mail' => ['john@example.org'], 'urn:other' => ['x']],
        ]);
        StepupGsspUserAttributeExtension::add($decorator, $assertion, ['urn:mace:dir:attribute-def:mail']);
        // Adding twice replaces the extension instead of duplicating it
        StepupGsspUserAttributeExtension::add($decorator, $assertion, ['urn:mace:dir:attribute-def:mail']);

        $restored = unserialize(serialize($decorator));
        $xml = $restored->toXml();

        $this->assertStringContainsString('<x:Custom xmlns:x="urn:example:custom">keep</x:Custom>', $xml);
        $this->assertSame(1, substr_count($xml, 'UserAttributes xmlns:gssp="urn:mace:surf.nl:stepup:gssp-extensions"'));
        $this->assertStringContainsString('Name="urn:mace:dir:attribute-def:mail"', $xml);
        $this->assertStringContainsString('john@example.org', $xml);
        $this->assertStringNotContainsString('urn:other', $xml);
    }

    public function test_state_from_another_release_is_reported_as_session_lost()
    {
        // Shape written by the saml2 4.x release: no format marker
        $legacy = self::serializedState(['_serializableSspMessageXml' => '<x/>', 'keyId' => null]);

        /** @var EngineBlock_Saml2_AuthnRequestAnnotationDecorator $restored */
        $restored = unserialize($legacy);

        $this->assertTrue($restored->isRestoredFromForeignState());
        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);
        $restored->assertRestored();
    }

    public function test_undecodable_state_is_reported_as_verification_failure_with_its_cause()
    {
        $state = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['id' => '_corrupt'])->__serialize();
        $state['_serializableSspMessageXml'] = str_replace('ID="_corrupt"', 'ID="1-not-an-NCName"', $state['_serializableSspMessageXml']);

        /** @var EngineBlock_Saml2_AuthnRequestAnnotationDecorator $restored */
        $restored = unserialize(self::serializedState($state));

        $this->assertFalse($restored->isRestoredFromForeignState());
        try {
            $restored->assertRestored();
            $this->fail('Expected a verification exception');
        } catch (EngineBlock_Corto_Module_Bindings_VerificationException $e) {
            $this->assertNotNull($e->getPrevious());
            $this->assertStringContainsString('Unable to decode the stored SAML message', $e->getMessage());
        }
    }

    private static function serializedState(array $state): string
    {
        $class = EngineBlock_Saml2_AuthnRequestAnnotationDecorator::class;

        return sprintf('O:%d:"%s"%s', strlen($class), $class, substr(serialize($state), 1));
    }
}
