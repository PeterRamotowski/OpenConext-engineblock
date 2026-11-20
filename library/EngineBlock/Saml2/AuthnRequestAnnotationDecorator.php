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

use OpenConext\EngineBlock\Metadata\Loa;
use OpenConext\EngineBlock\Saml2\Message\MessageRebuilder;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\AuthnContextComparisonTypeValue;
use SimpleSAML\SAML2\Type\EntityIDValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\AuthnContextClassRef;
use SimpleSAML\SAML2\XML\saml\NameID;
use SimpleSAML\SAML2\XML\saml\Subject;
use SimpleSAML\SAML2\XML\samlp\AbstractMessage;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\IDPEntry;
use SimpleSAML\SAML2\XML\samlp\IDPList;
use SimpleSAML\SAML2\XML\samlp\NameIDPolicy;
use SimpleSAML\SAML2\XML\samlp\RequestedAuthnContext;
use SimpleSAML\SAML2\XML\samlp\RequesterID;
use SimpleSAML\SAML2\XML\samlp\Scoping;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use SimpleSAML\XMLSchema\Type\NonNegativeIntegerValue;

class EngineBlock_Saml2_AuthnRequestAnnotationDecorator extends EngineBlock_Saml2_MessageAnnotationDecorator
{
    /**
     * @var AuthnRequest
     */
    #[Override]
    protected $sspMessage;

    /**
     * @var string
     */
    protected $keyId;

    /**
     * @var bool
     */
    protected $wasSigned = false;

    /**
     * @var bool
     */
    protected $debug = false;

    /**
     * @var bool
     */
    protected $unsolicited = false;

    /**
     * @var bool
     */
    protected $transparent = false;

    public function __construct(AuthnRequest $request, ?string $relayState = null)
    {
        $this->sspMessage = $request;
        $this->relayState = $relayState;
    }

    /**
     * @return AuthnRequest
     */
    #[Override]
    public function getSspMessage()
    {
        return parent::getSspMessage();
    }

    public function getForceAuthn(): bool
    {
        return $this->getSspMessage()->getForceAuthn()?->toBoolean() ?? false;
    }

    public function setForceAuthn(bool $isForceAuthn): static
    {
        // Like saml2 4.x only an enabled flag is emitted
        $this->rebuild(['forceAuthn' => $isForceAuthn ? BooleanValue::fromBoolean(true) : null]);
        return $this;
    }

    public function getIsPassive(): bool
    {
        return $this->getSspMessage()->getIsPassive()?->toBoolean() ?? false;
    }

    public function setIsPassive(bool $isPassive): static
    {
        $this->rebuild(['isPassive' => $isPassive ? BooleanValue::fromBoolean(true) : null]);
        return $this;
    }

    public function getAssertionConsumerServiceURL(): ?string
    {
        return $this->getSspMessage()->getAssertionConsumerServiceURL()?->getValue();
    }

    public function setAssertionConsumerServiceURL(?string $url): static
    {
        $this->rebuild(['assertionConsumerServiceURL' => $url === null ? null : SAMLAnyURIValue::fromString($url)]);
        return $this;
    }

    public function getAssertionConsumerServiceIndex(): ?int
    {
        $index = $this->getSspMessage()->getAssertionConsumerServiceIndex();
        return $index === null ? null : (int) $index->getValue();
    }

    public function getAttributeConsumingServiceIndex(): ?int
    {
        $index = $this->getSspMessage()->getAttributeConsumingServiceIndex();
        return $index === null ? null : (int) $index->getValue();
    }

    public function getProtocolBinding(): ?string
    {
        return $this->getSspMessage()->getProtocolBinding()?->getValue();
    }

    public function setProtocolBinding(?string $binding): static
    {
        $this->rebuild(['protocolBinding' => $binding === null ? null : SAMLAnyURIValue::fromString($binding)]);
        return $this;
    }

    public function getProviderName(): ?string
    {
        return $this->getSspMessage()->getProviderName()?->getValue();
    }

    /**
     * The NameID of the Subject of the request, if any.
     */
    public function getNameId(): ?NameID
    {
        $identifier = $this->getSspMessage()->getSubject()?->getIdentifier();
        return $identifier instanceof NameID ? $identifier : null;
    }

    public function setNameId(?NameID $nameId): static
    {
        $confirmations = $this->getSspMessage()->getSubject()?->getSubjectConfirmation() ?? [];
        $subject = $nameId === null && $confirmations === [] ? null : new Subject($nameId, $confirmations);
        $this->rebuild(['subject' => $subject]);
        return $this;
    }

    /**
     * @return array{Format?: string, SPNameQualifier?: string, AllowCreate?: bool}
     */
    public function getNameIdPolicy(): array
    {
        $policy = $this->getSspMessage()->getNameIdPolicy();
        if ($policy === null) {
            return [];
        }

        return array_filter([
            'Format' => $policy->getFormat()?->getValue(),
            'SPNameQualifier' => $policy->getSPNameQualifier()?->getValue(),
            'AllowCreate' => $policy->getAllowCreate()?->toBoolean(),
        ], static fn ($value) => $value !== null);
    }

    /**
     * @param array{Format?: string|null, SPNameQualifier?: string|null, AllowCreate?: bool|null}|null $policy
     */
    public function setNameIdPolicy(?array $policy): static
    {
        $format = $policy['Format'] ?? null;
        $spNameQualifier = $policy['SPNameQualifier'] ?? null;
        $allowCreate = $policy['AllowCreate'] ?? null;

        // SAML 2.0 errata E14: AllowCreate="true" must not be combined with the transient format.
        if ($format === Constants::NAMEID_TRANSIENT && $allowCreate === true) {
            $allowCreate = null;
        }

        $nameIdPolicy = null;
        if ($format !== null || $spNameQualifier !== null || $allowCreate !== null) {
            $nameIdPolicy = new NameIDPolicy(
                $format === null || $format === '' ? null : SAMLAnyURIValue::fromString($format),
                $spNameQualifier === null || $spNameQualifier === '' ? null : SAMLStringValue::fromString($spNameQualifier),
                $allowCreate === null ? null : BooleanValue::fromBoolean((bool) $allowCreate),
            );
        }

        $this->rebuild(['nameIdPolicy' => $nameIdPolicy]);
        return $this;
    }

    /**
     * @return array{AuthnContextClassRef: string[], Comparison: string}|null
     */
    public function getRequestedAuthnContext(): ?array
    {
        $requestedAuthnContext = $this->getSspMessage()->getRequestedAuthnContext();
        if ($requestedAuthnContext === null) {
            return null;
        }

        $classRefs = [];
        foreach ($requestedAuthnContext->getRequestedAuthnContexts() as $context) {
            if ($context instanceof AuthnContextClassRef) {
                $classRefs[] = trim($context->getContent()->getValue());
            }
        }

        return [
            'AuthnContextClassRef' => $classRefs,
            'Comparison' => $requestedAuthnContext->getComparison()?->getValue() ?? 'exact',
        ];
    }

    /**
     * @param array{AuthnContextClassRef?: string[], Comparison?: string|null}|null $requestedAuthnContext
     */
    public function setRequestedAuthnContext(?array $requestedAuthnContext): static
    {
        $classRefs = array_values(array_filter(
            (array) ($requestedAuthnContext['AuthnContextClassRef'] ?? []),
            static fn ($classRef) => $classRef !== null && $classRef !== ''
        ));

        $value = null;
        if ($classRefs !== []) {
            $comparison = $requestedAuthnContext['Comparison'] ?? null;
            $value = new RequestedAuthnContext(
                array_map(
                    static fn (string $classRef) => new AuthnContextClassRef(SAMLAnyURIValue::fromString($classRef)),
                    $classRefs
                ),
                // Like saml2 4.x the default (exact) comparison is not emitted
                $comparison === null || $comparison === 'exact'
                    ? null
                    : AuthnContextComparisonTypeValue::fromString($comparison),
            );
        }

        $this->rebuild(['requestedAuthnContext' => $value]);
        return $this;
    }

    public function getProxyCount(): ?int
    {
        $proxyCount = $this->getSspMessage()->getScoping()?->getProxyCount();
        return $proxyCount === null ? null : (int) $proxyCount->getValue();
    }

    public function setProxyCount(?int $proxyCount): static
    {
        $this->rebuildScoping(proxyCount: $proxyCount === null ? null : NonNegativeIntegerValue::fromString((string) $proxyCount));
        return $this;
    }

    /**
     * @return string[] EntityIds in Scoping > IDPList.
     */
    public function getIDPList(): array
    {
        $entries = $this->getSspMessage()->getScoping()?->getIDPList()?->getIdpEntry() ?? [];
        return array_map(static fn (IDPEntry $entry) => $entry->getProviderId()->getValue(), $entries);
    }

    /**
     * @param string[] $entityIds
     */
    public function setIDPList(array $entityIds): static
    {
        $entityIds = array_values(array_filter($entityIds, static fn ($entityId) => $entityId !== null && $entityId !== ''));
        $idpList = $entityIds === [] ? null : new IDPList(array_map(
            static fn (string $entityId) => new IDPEntry(EntityIDValue::fromString($entityId)),
            $entityIds
        ));
        $this->rebuildScoping(idpList: $idpList);
        return $this;
    }

    /**
     * @return string[] EntityIds in Scoping > RequesterID element.
     */
    public function getRequesterID(): array
    {
        $requesterIds = $this->getSspMessage()->getScoping()?->getRequesterId() ?? [];
        return array_map(static fn (RequesterID $requesterId) => $requesterId->getContent()->getValue(), $requesterIds);
    }

    /**
     * @return string[] EntityIds in Scoping > RequesterID element.
     */
    public function getRequesterIds(): array
    {
        return $this->getRequesterID();
    }

    /**
     * @param string[] $requesterIds
     */
    public function setRequesterID(array $requesterIds): static
    {
        $requesterIds = array_values(array_filter($requesterIds, static fn ($id) => $id !== null && $id !== ''));
        $this->rebuildScoping(requesterIds: array_map(
            static fn (string $requesterId) => new RequesterID(EntityIDValue::fromString($requesterId)),
            $requesterIds
        ));
        return $this;
    }

    /**
     * @return Loa[]
     * @param Loa[]
     */
    public function getStepupObligations(array $stepUpLoas)
    {
        $requestedAuthncontext = $this->getRequestedAuthnContext();
        $obligations = [];
        if ($requestedAuthncontext && $requestedAuthncontext['AuthnContextClassRef']) {
            foreach ($requestedAuthncontext['AuthnContextClassRef'] as $rac) {
                foreach ($stepUpLoas as $loa) {
                    if ($loa->getIdentifier() === $rac) {
                        $obligations[] = $loa;
                    }
                }
            }
        }
        return $obligations;
    }

    public function setDebugRequest()
    {
        $this->debug = true;
        return $this;
    }

    public function isDebugRequest()
    {
        return $this->debug;
    }

    public function getKeyId()
    {
        return $this->keyId;
    }

    /**
     * @param $keyId
     * @return $this
     */
    public function setKeyId($keyId)
    {
        $this->keyId = $keyId;
        return $this;
    }

    public function setWasSigned()
    {
        $this->wasSigned = true;
        return $this;
    }

    /**
     * @return bool
     */
    public function wasSigned()
    {
        return $this->wasSigned;
    }

    public function setUnsolicited()
    {
        $this->unsolicited = true;
        return $this;
    }

    public function isUnsolicited()
    {
        return $this->unsolicited;
    }

    public function setDebug()
    {
        $this->debug = true;
        return $this;
    }

    /**
     * @return boolean
     */
    public function getDebug()
    {
        return $this->debug;
    }

    /**
     * @return $this
     */
    public function setTransparent()
    {
        $this->transparent = true;
        return $this;
    }

    public function isTransparent()
    {
        return $this->transparent;
    }

    public function __serialize(): array
    {
        return $this->serializeMessageState() + [
            'keyId' => $this->keyId,
            'wasSigned' => $this->wasSigned,
            'debug' => $this->debug,
            'unsolicited' => $this->unsolicited,
            'transparent' => $this->transparent,
        ];
    }

    public function __unserialize(array $data): void
    {
        if (!$this->unserializeMessageState($data)) {
            return;
        }

        $this->keyId = $data['keyId'] ?? null;
        $this->wasSigned = (bool) ($data['wasSigned'] ?? false);
        $this->debug = (bool) ($data['debug'] ?? false);
        $this->unsolicited = (bool) ($data['unsolicited'] ?? false);
        $this->transparent = (bool) ($data['transparent'] ?? false);
    }

    #[Override]
    protected function rebuild(array $changes): void
    {
        $this->sspMessage = MessageRebuilder::authnRequest($this->getSspMessage(), $changes);
    }

    #[Override]
    protected function restoreMessage(string $xml): AbstractMessage
    {
        return AuthnRequest::fromXML(Saml2Value::documentElement($xml));
    }

    private function rebuildScoping(
        NonNegativeIntegerValue|false|null $proxyCount = false,
        IDPList|false|null $idpList = false,
        array|false $requesterIds = false,
    ): void {
        $scoping = $this->getSspMessage()->getScoping();
        $proxyCount = $proxyCount === false ? $scoping?->getProxyCount() : $proxyCount;
        $idpList = $idpList === false ? $scoping?->getIDPList() : $idpList;
        $requesterIds = $requesterIds === false ? ($scoping?->getRequesterId() ?? []) : $requesterIds;

        $newScoping = $proxyCount === null && $idpList === null && $requesterIds === []
            ? null
            : new Scoping($proxyCount, $idpList, $requesterIds);

        $this->rebuild(['scoping' => $newScoping]);
    }
}
