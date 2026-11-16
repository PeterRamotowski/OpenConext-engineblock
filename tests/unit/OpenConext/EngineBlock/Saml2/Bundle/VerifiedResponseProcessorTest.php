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

use OpenConext\EngineBlock\Saml2\Bundle\Exception\UnsupportedSignatureAlgorithmException;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\XmlSecurity;
use PHPUnit\Framework\Attributes\RequiresMethod;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Assertion\Exception\InvalidAssertionException;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Configuration\PrivateKey;
use SimpleSAML\SAML2\Response\Exception\InvalidSignatureException;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Surfnet\SamlBundle\SAML2\Response\LocalAssertionDecrypter;
use Surfnet\SamlBundle\SAML2\Response\ResponseProcessor;
use Symfony\Component\Clock\MockClock;

#[RequiresMethod(ResponseProcessor::class, 'process')]
class VerifiedResponseProcessorTest extends TestCase
{
    private const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    private const ACS = 'https://engine.example.com/authentication/sp/consume-assertion';
    private const SP_ENTITY_ID = 'https://engine.example.com/authentication/sp/metadata';
    private const IDP_ENTITY_ID = 'https://idp.example.com/metadata';
    private const REQUEST_ID = '_request';

    private ServiceProvider $serviceProvider;

    private array $keyFiles = [];

    private AbstractContainer $originalContainer;

    protected function setUp(): void
    {
        $this->originalContainer = ContainerSingleton::getInstance();
        ContainerSingleton::setContainer(new BridgeContainer(new NullLogger(), new MockClock('2026-11-04T12:00:00Z')));
        $this->serviceProvider = new ServiceProvider([
            'entityId' => self::SP_ENTITY_ID,
            'assertionConsumerUrl' => self::ACS,
            'privateKeys' => [],
        ]);
    }

    protected function tearDown(): void
    {
        ContainerSingleton::setContainer($this->originalContainer);
        foreach ($this->keyFiles as $file) {
            unlink($file);
        }
    }

    #[Test]
    public function aSignedResponseYieldsItsVerifiedEnvelopeAndTheValidatedAssertion(): void
    {
        $response = $this->signedResponse($this->response('_signed-envelope', $this->assertion()), 'idp', self::RSA_SHA512);

        $result = $this->processor()->process($this->serviceProvider, $this->identityProvider(), self::ACS, $response);

        self::assertTrue($result->hasVerifiedEnvelope());
        self::assertSame('_signed-envelope', $result->getVerifiedEnvelope()->getId()->getValue());
        self::assertSame(self::REQUEST_ID, $result->getVerifiedEnvelope()->getInResponseTo()->getValue());
        self::assertSame('john-doe', $result->getAssertion()->getSubject()->getIdentifier()->getContent()->getValue());
    }

    #[Test]
    public function anUnsignedResponseHasNoVerifiedEnvelope(): void
    {
        $response = $this->parse($this->response('_unsigned-envelope', $this->signedAssertion($this->assertion())));

        $result = $this->processor()->process($this->serviceProvider, $this->identityProvider(), self::ACS, $response);

        self::assertFalse($result->hasVerifiedEnvelope());
        self::assertNull($result->getVerifiedEnvelope());
        self::assertSame('john-doe', $result->getAssertion()->getSubject()->getIdentifier()->getContent()->getValue());
    }

    #[Test]
    public function everyConfiguredIdentityProviderKeyIsTried(): void
    {
        $identityProvider = new IdentityProvider([
            'entityId' => self::IDP_ENTITY_ID,
            'keys' => [
                $this->signingKey(GeneratedKeyPair::named('other')),
                $this->signingKey(GeneratedKeyPair::named('idp')),
            ],
        ]);
        $response = $this->signedResponse($this->response('_rollover', $this->assertion()), 'idp');

        $result = $this->processor()->process($this->serviceProvider, $identityProvider, self::ACS, $response);

        self::assertTrue($result->hasVerifiedEnvelope());
    }

    #[Test]
    public function anIdentityProviderCertificateFileIsTrusted(): void
    {
        $certificateFile = tempnam(sys_get_temp_dir(), 'eb-idp-cert');
        $certificate = GeneratedKeyPair::named('idp')->certificateData();
        file_put_contents(
            $certificateFile,
            "-----BEGIN CERTIFICATE-----\n" . chunk_split($certificate, 64, "\n") . "-----END CERTIFICATE-----\n"
        );
        $identityProvider = new IdentityProvider(['entityId' => self::IDP_ENTITY_ID, 'certificateFile' => $certificateFile]);
        $response = $this->signedResponse($this->response('_certificate-file', $this->assertion()), 'idp');

        try {
            $result = $this->processor()->process($this->serviceProvider, $identityProvider, self::ACS, $response);
        } finally {
            unlink($certificateFile);
        }

        self::assertTrue($result->hasVerifiedEnvelope());
    }

    #[Test]
    public function anEnvelopeSignedByAnUnconfiguredKeyIsRejectedBeforeProcessing(): void
    {
        $responseProcessor = $this->createMock(ResponseProcessor::class);
        $responseProcessor->expects(self::never())->method('process');
        $processor = new VerifiedResponseProcessor($responseProcessor, new ResponseEnvelopeVerifier(new NullLogger()));

        $this->expectException(InvalidSignatureException::class);

        $processor->process(
            $this->serviceProvider,
            $this->identityProvider(),
            self::ACS,
            $this->signedResponse($this->response('_untrusted', $this->assertion()), 'other')
        );
    }

    #[Test]
    public function anEnvelopeChangedAfterSigningIsRejected(): void
    {
        $signed = $this->signedResponseXml($this->response('_changed', $this->assertion()), 'idp');
        $changed = str_replace('InResponseTo="' . self::REQUEST_ID . '" IssueInstant', 'InResponseTo="_other" IssueInstant', $signed);
        self::assertNotSame($signed, $changed);

        $this->expectException(InvalidSignatureException::class);

        $this->processor()->process($this->serviceProvider, $this->identityProvider(), self::ACS, $this->parse($changed));
    }

    #[Test]
    public function anEnvelopeSignedWithABlacklistedAlgorithmIsRejected(): void
    {
        $response = $this->signedResponse($this->response('_sha1', $this->assertion()), 'idp', self::RSA_SHA1);

        $this->expectException(InvalidSignatureException::class);

        $this->processor()->process($this->serviceProvider, $this->identityProvider(), self::ACS, $response);
    }

    #[Test]
    public function anEnvelopeWithAForbiddenTransformIsRejected(): void
    {
        $document = DOMDocumentFactory::fromString(
            $this->signedResponseXml($this->response('_transform', $this->assertion()), 'idp')
        );
        $transform = $document->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Transform')->item(0);
        $transform->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xslt-19991116');

        $this->expectException(SignatureValidationFailedException::class);

        (new ResponseEnvelopeVerifier(new NullLogger()))->verify(
            $this->parse($document->saveXML($document->documentElement)),
            $this->identityProvider()
        );
    }

    #[Test]
    public function aVerifiedEnvelopeIsNotReturnedWhenTheAssertionIsInvalid(): void
    {
        $response = $this->signedResponse(
            $this->response('_wrong-audience', $this->assertion('https://other-sp.example.com/metadata')),
            'idp'
        );

        $this->expectException(InvalidAssertionException::class);

        $this->processor()->process($this->serviceProvider, $this->identityProvider(), self::ACS, $response);
    }

    #[Test]
    public function anEncryptedAssertionRetainsItsVerifiedAlgorithmWithoutLeakingItToTheNextResponse(): void
    {
        $encrypted = $this->encryptedAssertion($this->signedAssertion($this->assertion()));
        $response = $this->signedResponse($this->response('_encrypted', $encrypted), 'idp', self::RSA_SHA512);
        $decrypter = new PolicyCheckingAssertionDecrypter(new LocalAssertionDecrypter(new PrivateKeyLoader()));
        $processor = $this->processor($decrypter);

        $result = $processor->process($this->serviceProvider, $this->identityProvider(), self::ACS, $response);

        self::assertSame(self::RSA_SHA512, $result->getResponseSignatureMethod());
        self::assertSame(self::RSA_SHA256, $result->getAssertionSignatureMethod());
        self::assertSame('john-doe', $result->getAssertion()->getSubject()->getIdentifier()->getContent()->getValue());
        self::assertNull($decrypter->getSignatureMethod());

        $next = $this->signedResponse($this->response('_next', $this->assertion()), 'idp');
        $nextResult = $processor->process($this->serviceProvider, $this->identityProvider(), self::ACS, $next);
        self::assertNull($nextResult->getAssertionSignatureMethod());
    }

    #[Test]
    public function aConfiguredForbiddenAlgorithmInsideEncryptionIsRejected(): void
    {
        $encrypted = $this->encryptedAssertion($this->signedAssertion($this->assertion()));
        $response = $this->signedResponse($this->response('_forbidden-inner', $encrypted), 'idp', self::RSA_SHA512);
        $decrypter = new PolicyCheckingAssertionDecrypter(
            new LocalAssertionDecrypter(new PrivateKeyLoader()),
            [self::RSA_SHA256]
        );
        $this->expectException(UnsupportedSignatureAlgorithmException::class);

        try {
            $this->processor($decrypter, [self::RSA_SHA256])
                ->process($this->serviceProvider, $this->identityProvider(), self::ACS, $response);
        } finally {
            self::assertNull($decrypter->getSignatureMethod());
        }
    }

    private function encryptedAssertion(string $assertion): string
    {
        $key = GeneratedKeyPair::named('engine');
        $keyFile = tempnam(sys_get_temp_dir(), 'eb-decryption-key');
        $this->keyFiles[] = $keyFile;
        file_put_contents($keyFile, $key->privateKeyPem());
        $this->serviceProvider = new ServiceProvider([
            'entityId' => self::SP_ENTITY_ID,
            'assertionConsumerUrl' => self::ACS,
            'privateKeys' => [new PrivateKey($keyFile, PrivateKey::NAME_DEFAULT)],
        ]);

        $encrypted = XmlSecurity::encryptAssertion(
            DOMDocumentFactory::fromString($assertion)->documentElement,
            $key->certificateData(),
            null
        );

        return $encrypted->ownerDocument->saveXML($encrypted);
    }

    private function processor(
        ?PolicyCheckingAssertionDecrypter $decrypter = null,
        array $forbiddenAlgorithms = []
    ): VerifiedResponseProcessor {
        return new VerifiedResponseProcessor(
            new ResponseProcessor(new KeyLoader(), new PrivateKeyLoader(), new NullLogger(), assertionDecrypter: $decrypter),
            new ResponseEnvelopeVerifier(new NullLogger()),
            $decrypter,
            $forbiddenAlgorithms
        );
    }

    private function identityProvider(): IdentityProvider
    {
        return new IdentityProvider([
            'entityId' => self::IDP_ENTITY_ID,
            'certificateData' => GeneratedKeyPair::named('idp')->certificateData(),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function signingKey(GeneratedKeyPair $keyPair): array
    {
        return [
            'type' => 'X509Certificate',
            'signing' => true,
            'encryption' => false,
            'X509Certificate' => $keyPair->certificateData(),
        ];
    }

    private function assertion(string $audience = self::SP_ENTITY_ID): string
    {
        return sprintf(
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z"><saml:Issuer>%s</saml:Issuer>'
            . '<saml:Subject><saml:NameID>john-doe</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData NotOnOrAfter="2026-11-04T12:05:00Z" Recipient="%s" InResponseTo="%s"/>'
            . '</saml:SubjectConfirmation></saml:Subject>'
            . '<saml:Conditions NotBefore="2026-11-04T11:55:00Z" NotOnOrAfter="2026-11-04T12:05:00Z">'
            . '<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            . '<saml:AuthnStatement AuthnInstant="2026-11-04T12:00:00Z"><saml:AuthnContext>'
            . '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
            . '</saml:AuthnContext></saml:AuthnStatement></saml:Assertion>',
            bin2hex(random_bytes(16)),
            self::IDP_ENTITY_ID,
            self::ACS,
            self::REQUEST_ID,
            $audience
        );
    }

    private function response(string $id, string $assertion): string
    {
        return sprintf(
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z" Destination="%s" InResponseTo="%s">'
            . '<saml:Issuer>%s</saml:Issuer><samlp:Status>'
            . '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:Response>',
            $id,
            self::ACS,
            self::REQUEST_ID,
            self::IDP_ENTITY_ID,
            $assertion
        );
    }

    private function signedAssertion(string $assertionXml): string
    {
        $assertion = Assertion::fromXML(DOMDocumentFactory::fromString($assertionXml)->documentElement);
        $assertion->sign(
            (new SignatureAlgorithmFactory([]))->getAlgorithm(self::RSA_SHA256, GeneratedKeyPair::named('idp')->privateKey())
        );
        $xml = $assertion->toXML();

        return $xml->ownerDocument->saveXML($xml);
    }

    private function signedResponse(string $responseXml, string $signer, string $algorithm = self::RSA_SHA256): Response
    {
        return $this->parse($this->signedResponseXml($responseXml, $signer, $algorithm));
    }

    private function signedResponseXml(string $responseXml, string $signer, string $algorithm = self::RSA_SHA256): string
    {
        $response = $this->parse($responseXml);
        $response->sign(
            (new SignatureAlgorithmFactory([]))->getAlgorithm($algorithm, GeneratedKeyPair::named($signer)->privateKey())
        );
        $xml = $response->toXML();

        return $xml->ownerDocument->saveXML($xml);
    }

    private function parse(string $responseXml): Response
    {
        return Response::fromXML(DOMDocumentFactory::fromString($responseXml)->documentElement);
    }
}
