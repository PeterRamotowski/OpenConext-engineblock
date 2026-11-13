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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresMethod;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;
use Surfnet\SamlBundle\SAML2\AuthnRequest;

#[RequiresMethod(AuthnRequest::class, 'getUnsignedXML')]
class UnsignedRedirectEncoderTest extends TestCase
{
    private const DESTINATION = 'https://idp.example.com/sso';

    #[Test]
    public function theUnsignedRequestAndRelayStateAreEncoded(): void
    {
        $request = $this->authnRequest(self::DESTINATION);

        $query = ReceivedAuthnRequestQueryString::parse(
            (new UnsignedRedirectEncoder())->buildQuery($request, 'https://sp.example.com/page?a=1&b=2')
        );

        self::assertFalse($query->isSigned());
        self::assertSame($request->getUnsignedXML(), $query->getDecodedSamlRequest());
        self::assertSame('https://sp.example.com/page?a=1&b=2', urldecode($query->getRelayState()));
    }

    public static function absentRelayStates(): array
    {
        return ['null' => [null], 'empty' => ['']];
    }

    #[Test]
    #[DataProvider('absentRelayStates')]
    public function anAbsentRelayStateIsOmitted(?string $relayState): void
    {
        $query = (new UnsignedRedirectEncoder())->buildQuery($this->authnRequest(self::DESTINATION), $relayState);

        parse_str($query, $parameters);
        self::assertSame(['SAMLRequest'], array_keys($parameters));
    }

    #[Test]
    public function aRequestCreatedWithASignerIsNeitherSignedNorSentToTheSigner(): void
    {
        $signer = $this->createMock(SignatureAlgorithmInterface::class);
        $signer->expects(self::never())->method('sign');
        $signer->expects(self::never())->method('getAlgorithmId');

        $query = (new UnsignedRedirectEncoder())->buildQuery($this->authnRequest(self::DESTINATION, $signer), 'state');

        parse_str($query, $parameters);
        self::assertSame(['SAMLRequest', 'RelayState'], array_keys($parameters));
    }

    public static function destinations(): array
    {
        return [
            'without query' => [self::DESTINATION, self::DESTINATION . '?SAMLRequest='],
            'with query' => [self::DESTINATION . '?tenant=a', self::DESTINATION . '?tenant=a&SAMLRequest='],
        ];
    }

    #[Test]
    #[DataProvider('destinations')]
    public function theUrlExtendsTheDestination(string $destination, string $expectedPrefix): void
    {
        $url = (new UnsignedRedirectEncoder())->buildUrl($this->authnRequest($destination));

        self::assertStringStartsWith($expectedPrefix, $url);
    }

    private function authnRequest(string $destination, ?SignatureAlgorithmInterface $signer = null): AuthnRequest
    {
        $xml = sprintf(
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z" Destination="%s"'
            . ' AssertionConsumerServiceURL="https://sp.example.com/acs">'
            . '<saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>',
            htmlspecialchars($destination, ENT_XML1)
        );

        return AuthnRequest::createNew(
            SAML2AuthnRequest::fromXML(DOMDocumentFactory::fromString($xml)->documentElement),
            $signer
        );
    }
}
