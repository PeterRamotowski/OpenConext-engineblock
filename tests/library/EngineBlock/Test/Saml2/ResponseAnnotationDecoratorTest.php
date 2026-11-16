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

use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\XML\samlp\Response;

class EngineBlock_Test_Saml2_ResponseAnnotationDecoratorTest extends TestCase
{
    public function test_relaystate_persists_through_serialization()
    {
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse(['id' => 'RS1'], 'ss:mem:response-relay-456');

        $restored = unserialize(serialize($decorator));

        $this->assertEquals('ss:mem:response-relay-456', $restored->getRelayState(), 'RelayState should survive serialization in Response');
        $this->assertSame(Response::class, get_class($restored->getSspMessage()));
        $this->assertSame('RS1', $restored->getId());
    }

    public function test_annotations_survive_serialization()
    {
        $original = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse(['id' => '_original']);
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse([
            'id' => '_response',
            'inResponseTo' => '_request',
            'assertion' => ['nameId' => 'john', 'attributes' => ['urn:mail' => ['john@example.org']], 'classRef' => 'urn:loa1'],
        ]);
        $decorator->setOriginalResponse($original);
        $decorator->setOriginalIssuer('https://idp.example.org');
        $decorator->setOriginalBinding(Constants::BINDING_HTTP_POST);
        $decorator->setOriginalNameId(Saml2Value::nameId('original', Constants::NAMEID_PERSISTENT, 'https://idp'));
        $decorator->setCustomNameId(Saml2Value::nameId('custom', Constants::NAMEID_UNSPECIFIED));
        $decorator->setCollabPersonId('urn:collab:person:example.org:john');
        $decorator->setIntendedNameId('intended');
        $decorator->setPdpRequestedLoas(['urn:loa2']);
        $decorator->setSramInterruptNonce('nonce');
        $decorator->setIsTransparentErrorResponse(true);
        $decorator->setReturn('https://engine/consent');
        $decorator->setConsent(Constants::CONSENT_OBTAINED);

        /** @var EngineBlock_Saml2_ResponseAnnotationDecorator $restored */
        $restored = unserialize(serialize($decorator));
        $restored->assertRestored();

        $this->assertSame('_response', $restored->getId());
        $this->assertSame('_request', $restored->getInResponseTo());
        $this->assertSame('john', $restored->getNameIdValue());
        $this->assertSame(['urn:mail' => ['john@example.org']], $restored->getAttributes());
        $this->assertSame('urn:loa1', $restored->getAuthnContextClassRef());
        $this->assertSame(Constants::CONSENT_OBTAINED, $restored->getConsent());
        $this->assertSame('_original', $restored->getOriginalResponse()->getId());
        $this->assertSame('https://idp.example.org', $restored->getOriginalIssuer());
        $this->assertSame(Constants::BINDING_HTTP_POST, $restored->getOriginalBinding());
        $this->assertSame('original', Saml2Value::nameIdValue($restored->getOriginalNameId()));
        $this->assertSame('https://idp', $restored->getOriginalNameId()->getNameQualifier()->getValue());
        $this->assertSame('custom', Saml2Value::nameIdValue($restored->getCustomNameId()));
        $this->assertSame('urn:collab:person:example.org:john', $restored->getCollabPersonId());
        $this->assertSame('intended', $restored->getIntendedNameId());
        $this->assertSame(['urn:loa2'], $restored->getPdpRequestedLoas());
        $this->assertSame('nonce', $restored->getSramInterruptNonce());
        $this->assertTrue($restored->isTransparentErrorResponse());
        $this->assertSame('https://engine/consent', $restored->getReturn());
    }

    public function test_attribute_value_types_survive_serialization()
    {
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse();
        $decorator->setAttributesValueTypes(['urn:age' => ['xs:integer']]);

        $restored = unserialize(serialize($decorator));
        $restored->setAttributes(['urn:age' => ['42'], 'urn:mail' => ['john@example.org']]);

        $xml = $restored->toXml();
        $this->assertMatchesRegularExpression('#Name="urn:age"[^>]*><saml:AttributeValue [^>]*xsi:type="xs:integer">42<#', $xml);
        $this->assertMatchesRegularExpression('#Name="urn:mail"[^>]*><saml:AttributeValue [^>]*xsi:type="xs:string">john@#', $xml);
    }

    public function test_changes_rebuild_the_message_instead_of_mutating_it()
    {
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse([
            'assertion' => ['nameId' => 'john', 'classRef' => 'urn:loa1'],
        ]);
        $before = $decorator->getSspMessage();

        $decorator->setAttributes(['urn:mail' => ['john@example.org']]);
        $decorator->setAuthnContextClassRef('urn:loa2');
        $decorator->setNameId(Saml2Value::nameId('jane', Constants::NAMEID_PERSISTENT));

        $this->assertNotSame($before, $decorator->getSspMessage());
        $this->assertSame([], (new EngineBlock_Saml2_ResponseAnnotationDecorator($before))->getAttributes());
        $this->assertSame(['urn:mail' => ['john@example.org']], $decorator->getAttributes());
        $this->assertSame('urn:loa2', $decorator->getAuthnContextClassRef());
        $this->assertSame('jane', $decorator->getNameIdValue());
        $this->assertSame(Constants::NAMEID_PERSISTENT, $decorator->getNameIdFormat());
    }

    public function test_status_is_exposed_in_the_legacy_shape()
    {
        $decorator = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse([
            'status' => ['Code' => Constants::STATUS_RESPONDER, 'SubCode' => Constants::STATUS_NO_PASSIVE, 'Message' => 'No passive'],
        ]);

        $this->assertFalse($decorator->isSuccess());
        $this->assertSame(
            ['Code' => Constants::STATUS_RESPONDER, 'SubCode' => Constants::STATUS_NO_PASSIVE, 'Message' => 'No passive'],
            $decorator->getStatus()
        );
    }

    public function test_stale_original_response_is_reported_as_session_lost()
    {
        $state = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse()->__serialize();
        $state['originalResponse'] = unserialize(
            sprintf(
                'O:%d:"%s"%s',
                strlen(EngineBlock_Saml2_ResponseAnnotationDecorator::class),
                EngineBlock_Saml2_ResponseAnnotationDecorator::class,
                substr(serialize(['_serializableSspMessageXml' => '<x/>']), 1)
            )
        );
        $restored = new EngineBlock_Saml2_ResponseAnnotationDecorator(EngineBlock_Test_Saml2_MessageFixtures::response());
        $restored->__unserialize($state);

        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);
        $restored->assertRestored();
    }
}
