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

namespace OpenConext\EngineBlockFunctionalTestingBundle\Saml2;

use Dom\Element;
use EngineBlock_Saml2_ResponseAnnotationDecorator;
use OpenConext\EngineBlock\Saml2\Message\MessageRebuilder;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Exception\ProtocolViolationException;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\Response as SamlResponse;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;

/**
 * The Response a mock IdP sends: a (mutable) saml2 v7 Response plus the signing and encryption configuration.
 *
 * Signing and encryption are applied to the serialized DOM when the XML is generated, so values saml2 v7 refuses
 * to model (e.g. an invalid AuthnContextClassRef) can still be sent, and the XML can be overridden altogether.
 */
class Response
{
    private EngineBlock_Saml2_ResponseAnnotationDecorator $response;

    /**
     * Raw XML that replaces the generated XML.
     */
    private ?string $xml = null;

    private ?SignatureAlgorithmInterface $responseSigner = null;

    private ?SignatureAlgorithmInterface $assertionSigner = null;

    private ?KeyInfo $assertionKeyInfo = null;

    private ?string $encryptionCertificate = null;

    private ?string $encryptionSharedKey = null;

    /**
     * AuthnContextClassRef written to the raw XML of the assertions, for values that are not a valid URI.
     */
    private ?string $authnContextClassRefOverride = null;

    public function __construct(SamlResponse $response, ?string $relayState = null)
    {
        $this->response = new EngineBlock_Saml2_ResponseAnnotationDecorator($response, $relayState);
    }

    public static function fromXml(string $xml): self
    {
        return new self(SamlResponse::fromXML(Saml2Value::documentElement($xml)));
    }

    public function getDecorator(): EngineBlock_Saml2_ResponseAnnotationDecorator
    {
        return $this->response;
    }

    public function getSspMessage(): SamlResponse
    {
        return $this->response->getSspMessage();
    }

    public function getId(): string
    {
        return $this->response->getId();
    }

    public function getIssuerValue(): ?string
    {
        return $this->response->getIssuerValue();
    }

    public function setIssuer(?string $issuer): self
    {
        $this->response->setIssuer($issuer);
        return $this;
    }

    public function getDestination(): ?string
    {
        return $this->response->getDestination();
    }

    public function setDestination(?string $destination): self
    {
        $this->response->setDestination($destination);
        return $this;
    }

    public function getInResponseTo(): ?string
    {
        return $this->response->getInResponseTo();
    }

    public function setInResponseTo(?string $inResponseTo): self
    {
        $this->response->setInResponseTo($inResponseTo);
        return $this;
    }

    /**
     * @return array{Code: string, SubCode: string|null, Message: string|null}
     */
    public function getStatus(): array
    {
        return $this->response->getStatus();
    }

    public function setStatus(array $status): self
    {
        $this->response->setStatus($status);
        return $this;
    }

    /**
     * @return Assertion[]
     */
    public function getAssertions(): array
    {
        return $this->response->getAssertions();
    }

    /**
     * @param Assertion[] $assertions
     */
    public function setAssertions(array $assertions): self
    {
        $this->response->setAssertions($assertions);
        return $this;
    }

    public function getAssertion(): Assertion
    {
        return $this->response->getAssertion();
    }

    public function setAssertion(Assertion $assertion): self
    {
        $this->response->setAssertion($assertion);
        return $this;
    }

    /**
     * @return array<string, list<mixed>>
     */
    public function getAttributes(): array
    {
        return $this->response->getAttributes();
    }

    public function setAttributes(array $attributes): self
    {
        $this->response->setAttributes($attributes);
        return $this;
    }

    public function getAuthnContextClassRef(): ?string
    {
        return $this->authnContextClassRefOverride ?? $this->response->getAuthnContextClassRef();
    }

    /**
     * Values that are not a valid URI are written to the raw XML, so EngineBlock can be tested to reject them.
     */
    public function setAuthnContextClassRef(?string $classRef): self
    {
        $this->authnContextClassRefOverride = null;
        try {
            $this->response->setAuthnContextClassRef($classRef);
        } catch (ProtocolViolationException) {
            $this->authnContextClassRefOverride = $classRef;
        }

        return $this;
    }

    public function setResponseSigner(?SignatureAlgorithmInterface $signer): self
    {
        $this->responseSigner = $signer;
        return $this;
    }

    public function setAssertionSigner(?SignatureAlgorithmInterface $signer, ?KeyInfo $keyInfo = null): self
    {
        $this->assertionSigner = $signer;
        $this->assertionKeyInfo = $keyInfo;
        return $this;
    }

    public function getResponseSigner(): ?SignatureAlgorithmInterface
    {
        return $this->responseSigner;
    }

    /**
     * Encrypt the assertions with RSA-OAEP to the certificate (PEM or certificate data), or with a shared key.
     */
    public function encryptAssertions(?string $certificate, ?string $sharedKey = null): self
    {
        $this->encryptionCertificate = $certificate;
        $this->encryptionSharedKey = $sharedKey;
        return $this;
    }

    public function setXml(?string $xml): ?string
    {
        $this->xml = $xml;
        return $xml;
    }

    /**
     * The XML document, with signed and/or encrypted assertions and, when requested, an enveloped response signature.
     */
    public function toXml(bool $signResponse = true): string
    {
        if ($this->xml !== null) {
            return $this->xml;
        }

        $message = $this->getSspMessage();
        $response = Saml2Value::documentElement(
            Saml2Value::toXmlString(
                MessageRebuilder::response($message, ['assertions' => []])
            )
        );
        $document = $response->ownerDocument;

        foreach ($message->getAssertions() as $assertion) {
            $response->appendChild($document->importNode($this->processAssertion($assertion), true));
        }

        if ($signResponse && $this->responseSigner !== null) {
            XmlSecurity::signEnveloped($response, $this->responseSigner);
        }

        return $document->saveXml();
    }

    private function processAssertion(object $assertion): Element
    {
        $element = Saml2Value::documentElement(Saml2Value::toXmlString($assertion));
        if (!$assertion instanceof Assertion) {
            return $element;
        }

        if ($this->authnContextClassRefOverride !== null) {
            foreach ($element->getElementsByTagNameNS(Constants::NS_SAML, 'AuthnContextClassRef') as $classRef) {
                $classRef->textContent = $this->authnContextClassRefOverride;
            }
        }

        if ($this->assertionSigner !== null) {
            XmlSecurity::signEnveloped($element, $this->assertionSigner, $this->assertionKeyInfo);
        }

        if ($this->encryptionCertificate !== null || $this->encryptionSharedKey !== null) {
            return XmlSecurity::encryptAssertion($element, $this->encryptionCertificate, $this->encryptionSharedKey);
        }

        return $element;
    }

    public function __clone()
    {
        $this->response = clone $this->response;
    }
}
