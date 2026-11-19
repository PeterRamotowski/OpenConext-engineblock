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

use OpenConext\EngineBlock\Saml2\Message\AttributeMapper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Response;

class EngineBlock_Test_Saml2_MessageSerializerTest extends TestCase
{
    public function testResponseRoundTrip(): void
    {
        $serializer = new EngineBlock_Saml2_MessageSerializer();
        $response = EngineBlock_Test_Saml2_MessageFixtures::response([
            'inResponseTo' => '_request',
            'destination' => 'https://sp.example.org/acs',
            'assertion' => ['nameId' => 'subject', 'attributes' => ['urn:mace:dir:attribute-def:uid' => ['joe']]],
        ]);

        $xml = $serializer->serialize($response);
        $restored = $serializer->deserialize($xml, Response::class);

        $this->assertInstanceOf(Response::class, $restored);
        $this->assertSame('_request', $restored->getInResponseTo()?->getValue());
        $this->assertSame(
            AttributeMapper::toFlat($response->getAssertions()[0]),
            AttributeMapper::toFlat($restored->getAssertions()[0])
        );
        // saml2 v7 re-emits parsed xs:string values untyped; the outgoing pipeline re-types them via setAttributes()
        $reserialized = $serializer->serialize($restored);
        $this->assertSame($reserialized, $serializer->serialize($serializer->deserialize($reserialized, Response::class)));
    }

    public function testAuthnRequestRoundTrip(): void
    {
        $serializer = new EngineBlock_Saml2_MessageSerializer();
        $request = EngineBlock_Test_Saml2_MessageFixtures::authnRequest([
            'acsUrl' => 'https://sp.example.org/acs',
            'forceAuthn' => true,
        ]);

        $xml = $serializer->serialize($request);
        $restored = $serializer->deserialize($xml, AuthnRequest::class);

        $this->assertInstanceOf(AuthnRequest::class, $restored);
        $this->assertSame($xml, $serializer->serialize($restored));
    }

    #[DataProvider('invalidXmlProvider')]
    public function testInvalidXmlIsAVerificationFailureWithItsCause(string $xml, string $class): void
    {
        try {
            (new EngineBlock_Saml2_MessageSerializer())->deserialize($xml, $class);
            $this->fail('Expected a verification exception');
        } catch (EngineBlock_Corto_Module_Bindings_VerificationException $e) {
            $this->assertSame(EngineBlock_Exception::CODE_NOTICE, $e->getSeverity());
            $this->assertNotNull($e->getPrevious());
            $this->assertStringContainsString($e->getPrevious()->getMessage(), $e->getMessage());
        }
    }

    public static function invalidXmlProvider(): array
    {
        $request = (new EngineBlock_Saml2_MessageSerializer())->serialize(
            EngineBlock_Test_Saml2_MessageFixtures::authnRequest()
        );

        return [
            'not xml' => ['this is not xml', Response::class],
            'other message type' => [$request, Response::class],
            'nested message' => ['<wrapper>' . preg_replace('/^<\?xml[^>]+>\s*/', '', $request) . '</wrapper>', AuthnRequest::class],
            'schema violation' => [str_replace('Version="2.0"', 'Version="1.1"', $request), AuthnRequest::class],
        ];
    }

    public function testUnsupportedMessageClassIsRejected(): void
    {
        $this->expectException(EngineBlock_Exception::class);
        $this->expectExceptionMessage('Unknown message type');

        (new EngineBlock_Saml2_MessageSerializer())->deserialize('<x/>', stdClass::class);
    }
}
