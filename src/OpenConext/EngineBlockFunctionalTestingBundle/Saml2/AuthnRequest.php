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
use EngineBlock_Saml2_AuthnRequestAnnotationDecorator;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use SimpleSAML\SAML2\Exception\ProtocolViolationException;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SamlAuthnRequest;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;

/**
 * The AuthnRequest a mock SP sends: a (mutable) saml2 v7 AuthnRequest with its RelayState, signing configuration
 * and support for values saml2 v7 refuses to model (e.g. a relative ACS location) or a raw XML override.
 *
 * Only plain data is serialized (the unsigned XML), so it can be persisted in the mock entity registry.
 */
class AuthnRequest
{
    private const ATTRIBUTE_ACS_URL = 'AssertionConsumerServiceURL';

    private EngineBlock_Saml2_AuthnRequestAnnotationDecorator $request;

    /**
     * Raw XML that replaces the generated XML.
     */
    private ?string $xml = null;

    /**
     * Attributes of the samlp:AuthnRequest element saml2 v7 cannot model, written to the raw XML.
     *
     * @var array<string, string>
     */
    private array $attributeOverrides = [];

    private ?SignatureAlgorithmInterface $signer = null;

    public function __construct(SamlAuthnRequest $request, ?string $relayState = null)
    {
        $this->request = new EngineBlock_Saml2_AuthnRequestAnnotationDecorator($request, $relayState);
    }

    public static function create(string $issuer): self
    {
        return new self(new SamlAuthnRequest(
            id: IDValue::fromString(HttpBinding::generateId()),
            issueInstant: Saml2Value::dateTime(time()),
            issuer: Saml2Value::issuer($issuer),
        ));
    }

    public static function fromXml(string $xml, ?string $relayState = null): self
    {
        return new self(SamlAuthnRequest::fromXML(Saml2Value::documentElement($xml)), $relayState);
    }

    public function getDecorator(): EngineBlock_Saml2_AuthnRequestAnnotationDecorator
    {
        return $this->request;
    }

    public function getSspMessage(): SamlAuthnRequest
    {
        return $this->request->getSspMessage();
    }

    public function getId(): string
    {
        return $this->request->getId();
    }

    public function getIssuerValue(): ?string
    {
        return $this->request->getIssuerValue();
    }

    public function getDestination(): ?string
    {
        return $this->request->getDestination();
    }

    public function setDestination(?string $destination): self
    {
        $this->request->setDestination($destination);
        return $this;
    }

    public function getAssertionConsumerServiceURL(): ?string
    {
        return $this->attributeOverrides[self::ATTRIBUTE_ACS_URL] ?? $this->request->getAssertionConsumerServiceURL();
    }

    /**
     * Invalid locations (e.g. without scheme) are written to the raw XML, so EngineBlock can be tested to reject them.
     */
    public function setAssertionConsumerServiceURL(?string $url): self
    {
        unset($this->attributeOverrides[self::ATTRIBUTE_ACS_URL]);
        try {
            $this->request->setAssertionConsumerServiceURL($url);
        } catch (ProtocolViolationException) {
            $this->request->setAssertionConsumerServiceURL(null);
            $this->attributeOverrides[self::ATTRIBUTE_ACS_URL] = $url;
        }

        return $this;
    }

    public function getRequestedAuthnContext(): ?array
    {
        return $this->request->getRequestedAuthnContext();
    }

    public function setRequestedAuthnContext(?array $requestedAuthnContext = null): self
    {
        $this->request->setRequestedAuthnContext($requestedAuthnContext);
        return $this;
    }

    public function getRequesterID(): array
    {
        return $this->request->getRequesterID();
    }

    public function setRequesterID(array $requesterIds): self
    {
        $this->request->setRequesterID($requesterIds);
        return $this;
    }

    public function getIDPList(): array
    {
        return $this->request->getIDPList();
    }

    public function setIDPList(array $entityIds): self
    {
        $this->request->setIDPList($entityIds);
        return $this;
    }

    public function setProxyCount(?int $proxyCount): self
    {
        $this->request->setProxyCount($proxyCount);
        return $this;
    }

    public function setIsPassive(bool $isPassive): self
    {
        $this->request->setIsPassive($isPassive);
        return $this;
    }

    public function setProtocolBinding(?string $binding): self
    {
        $this->request->setProtocolBinding($binding);
        return $this;
    }

    public function getRelayState(): ?string
    {
        return $this->request->getRelayState();
    }

    public function setRelayState(?string $relayState): self
    {
        $this->request->setRelayState($relayState);
        return $this;
    }

    /**
     * Sign the request: an enveloped signature for HTTP-POST, a query signature for HTTP-Redirect.
     */
    public function setSigner(?SignatureAlgorithmInterface $signer): self
    {
        $this->signer = $signer;
        return $this;
    }

    public function getSigner(): ?SignatureAlgorithmInterface
    {
        return $this->signer;
    }

    public function setXml(?string $xml): ?string
    {
        $this->xml = $xml;
        return $xml;
    }

    /**
     * The unsigned XML (as used in the HTTP-Redirect binding), or the raw XML override.
     */
    public function toXml(): string
    {
        if ($this->xml !== null) {
            return $this->xml;
        }

        if ($this->attributeOverrides === []) {
            return $this->request->toXml();
        }

        return $this->toDocumentElement()->ownerDocument->saveXml();
    }

    /**
     * The XML with an enveloped signature when a signer is set (as used in the HTTP-POST binding).
     */
    public function toSignedXml(): string
    {
        if ($this->xml !== null || $this->signer === null) {
            return $this->toXml();
        }

        $element = $this->toDocumentElement();
        XmlSecurity::signEnveloped($element, $this->signer);

        return $element->ownerDocument->saveXml();
    }

    private function toDocumentElement(): Element
    {
        $element = Saml2Value::documentElement($this->request->toXml());
        foreach ($this->attributeOverrides as $name => $value) {
            $element->setAttribute($name, $value);
        }

        return $element;
    }

    public function __clone()
    {
        $this->request = clone $this->request;
    }

    public function __serialize(): array
    {
        return [
            'xml' => $this->request->toXml(),
            'relayState' => $this->request->getRelayState(),
            'xmlOverride' => $this->xml,
            'attributeOverrides' => $this->attributeOverrides,
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->request = new EngineBlock_Saml2_AuthnRequestAnnotationDecorator(
            SamlAuthnRequest::fromXML(Saml2Value::documentElement($data['xml'])),
            $data['relayState'] ?? null
        );
        $this->xml = $data['xmlOverride'] ?? null;
        $this->attributeOverrides = $data['attributeOverrides'] ?? [];
        $this->signer = null;
    }
}
