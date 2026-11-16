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
use OpenConext\EngineBlock\Saml2\Message\MessageRebuilder;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\AuthnContextClassRef;
use SimpleSAML\SAML2\XML\saml\NameID;
use SimpleSAML\SAML2\XML\samlp\AbstractMessage;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\SAML2\XML\samlp\Status;
use SimpleSAML\SAML2\XML\samlp\StatusCode;
use SimpleSAML\SAML2\XML\samlp\StatusMessage;
use SimpleSAML\XMLSchema\Type\NCNameValue;

class EngineBlock_Saml2_ResponseAnnotationDecorator extends EngineBlock_Saml2_MessageAnnotationDecorator
{
    /**
     * @var Response
     */
    #[Override]
    protected $sspMessage;

    /**
     * @var string
     */
    protected $return;

    /**
     * @var string
     */
    protected $originalIssuer;

    /**
     * @var NameID|null
     */
    protected $originalNameId;

    /**
     * @var string
     */
    protected $originalBinding;

    /**
     * @var EngineBlock_Saml2_ResponseAnnotationDecorator
     */
    protected $originalResponse;

    /**
     * @var string
     */
    protected $collabPersonId;

    /**
     * @var NameID|null
     */
    protected $customNameId;

    /**
     * @var string
     */
    protected $intendedNameId;

    /**
     * @var array
     */
    protected $pdpRequestedLoas = [];

    /**
     * @var bool
     */
    protected $isTransparentErrorResponse = false;

    protected string $SramInterruptNonce = "";

    /**
     * xsi:types to use when (re)writing the attributes, see AttributeMapper::toStatement().
     */
    private array $attributeValueTypes = [];

    /**
     * Algorithms of the signatures verified on receipt. The verified message no longer carries them,
     * and they are only checked in the receiving request, so they are not serialized.
     */
    private ?string $verifiedSignatureMethod = null;

    private ?string $verifiedAssertionSignatureMethod = null;

    private bool $hasVerifiedSignatureMethods = false;

    public function __construct(Response $response, ?string $relayState = null)
    {
        $this->sspMessage = $response;
        $this->relayState = $relayState;
    }

    /**
     * @return Response
     */
    #[Override]
    public function getSspMessage()
    {
        return parent::getSspMessage();
    }

    /**
     * @return Assertion
     * @throws RuntimeException
     */
    public function getAssertion()
    {
        $assertions = $this->getSspMessage()->getAssertions();
        if (empty($assertions)) {
            throw new RuntimeException('No assertions in response?');
        }
        if (!$assertions[0] instanceof Assertion) {
            throw new RuntimeException('Response contains an encrypted assertion that has not been decrypted');
        }
        return $assertions[0];
    }

    public function hasAssertion(): bool
    {
        $assertions = $this->getSspMessage()->getAssertions();
        return isset($assertions[0]) && $assertions[0] instanceof Assertion;
    }

    public function setAssertion(Assertion $assertion): static
    {
        $assertions = $this->getSspMessage()->getAssertions();
        $assertions[0] = $assertion;
        $this->rebuild(['assertions' => array_values($assertions)]);
        return $this;
    }

    /**
     * @return array<Assertion|\SimpleSAML\SAML2\XML\saml\EncryptedAssertion>
     */
    public function getAssertions(): array
    {
        return $this->getSspMessage()->getAssertions();
    }

    public function setAssertions(array $assertions): static
    {
        $this->rebuild(['assertions' => array_values($assertions)]);
        return $this;
    }

    public function getNameId(): ?NameID
    {
        $identifier = $this->getAssertion()->getSubject()?->getIdentifier();
        return $identifier instanceof NameID ? $identifier : null;
    }

    public function setNameId(?NameID $nameId): static
    {
        return $this->setAssertion(MessageRebuilder::assertionWithSubjectIdentifier($this->getAssertion(), $nameId));
    }

    /**
     * @return string
     */
    public function getNameIdValue()
    {
        $nameId = $this->getNameId();
        if (!$nameId) {
            throw new RuntimeException('No NameID in Assertion?');
        }
        return $nameId->getContent()->getValue();
    }

    /**
     * @return string
     */
    public function getNameIdFormat()
    {
        $format = $this->getNameId()?->getFormat()?->getValue();
        if (!$format) {
            throw new RuntimeException('No NameID in Assertion?');
        }
        return $format;
    }

    /**
     * @return array<string, list<mixed>>
     */
    public function getAttributes(): array
    {
        return AttributeMapper::toFlat($this->getAssertion());
    }

    public function setAttributes(array $attributes): static
    {
        $statement = AttributeMapper::toStatement(
            $attributes,
            $this->getAttributeNameFormat(),
            $this->attributeValueTypes
        );
        return $this->setAssertion(MessageRebuilder::assertionWithAttributeStatement($this->getAssertion(), $statement));
    }

    /**
     * Set the xsi:types of the attribute values. Values without a type are typed after their PHP type.
     */
    public function setAttributesValueTypes(array $valueTypes): static
    {
        $this->attributeValueTypes = $valueTypes;
        if ($this->hasAssertion()) {
            $this->setAttributes($this->getAttributes());
        }
        return $this;
    }

    public function getAttributeNameFormat(): string
    {
        return AttributeMapper::nameFormat($this->getAssertion());
    }

    public function setAttributeNameFormat(string $nameFormat): static
    {
        $statement = AttributeMapper::toStatement($this->getAttributes(), $nameFormat, $this->attributeValueTypes);
        return $this->setAssertion(MessageRebuilder::assertionWithAttributeStatement($this->getAssertion(), $statement));
    }

    public function getAuthnContextClassRef(): ?string
    {
        foreach ($this->getAssertion()->getAuthnStatements() as $authnStatement) {
            $classRef = $authnStatement->getAuthnContext()->getAuthnContextClassRef();
            if ($classRef !== null) {
                return trim($classRef->getContent()->getValue());
            }
        }
        return null;
    }

    public function setAuthnContextClassRef(?string $classRef): static
    {
        $assertion = $this->getAssertion();
        $authnStatements = $assertion->getAuthnStatements();
        if ($authnStatements === []) {
            throw new RuntimeException('No AuthnStatement in Assertion?');
        }

        $authnContext = MessageRebuilder::authnContext($authnStatements[0]->getAuthnContext(), [
            'authnContextClassRef' => $classRef === null
                ? null
                : new AuthnContextClassRef(SAMLAnyURIValue::fromString($classRef)),
        ]);

        return $this->setAssertion(
            MessageRebuilder::assertionWithAuthnStatement($assertion, ['authnContext' => $authnContext])
        );
    }

    /**
     * Algorithm of the enveloped signature of the (first) assertion, if any.
     */
    public function getAssertionSignatureMethod(): ?string
    {
        if ($this->hasVerifiedSignatureMethods) {
            return $this->verifiedAssertionSignatureMethod;
        }

        return $this->getAssertion()
            ->getSignature()
            ?->getSignedInfo()
            ->getSignatureMethod()
            ->getAlgorithm()
            ->getValue();
    }

    #[Override]
    public function getSignatureMethod(): ?string
    {
        return $this->hasVerifiedSignatureMethods ? $this->verifiedSignatureMethod : parent::getSignatureMethod();
    }

    public function setVerifiedSignatureMethods(?string $responseMethod, ?string $assertionMethod): static
    {
        $this->hasVerifiedSignatureMethods = true;
        $this->verifiedSignatureMethod = $responseMethod;
        $this->verifiedAssertionSignatureMethod = $assertionMethod;
        return $this;
    }

    /**
     * @return array{Code: string, SubCode: string|null, Message: string|null}
     */
    public function getStatus(): array
    {
        $status = $this->getSspMessage()->getStatus();
        $subCodes = $status->getStatusCode()->getSubCodes();

        return [
            'Code' => $status->getStatusCode()->getValue()->getValue(),
            'SubCode' => isset($subCodes[0]) ? $subCodes[0]->getValue()->getValue() : null,
            'Message' => $status->getStatusMessage()?->getContent()->getValue(),
        ];
    }

    /**
     * @param array{Code: string, SubCode?: string|null, Message?: string|null} $status
     */
    public function setStatus(array $status): static
    {
        $this->rebuild(['status' => self::createStatus($status)]);
        return $this;
    }

    public function isSuccess(): bool
    {
        return $this->getSspMessage()->isSuccess();
    }

    public function getInResponseTo(): ?string
    {
        return $this->getSspMessage()->getInResponseTo()?->getValue();
    }

    public function setInResponseTo(?string $inResponseTo): static
    {
        $this->rebuild([
            'inResponseTo' => $inResponseTo === null || $inResponseTo === ''
                ? null
                : NCNameValue::fromString($inResponseTo),
        ]);
        return $this;
    }

    /**
     * @param array{Code: string, SubCode?: string|null, Message?: string|null} $status
     */
    public static function createStatus(array $status): Status
    {
        $subCodes = empty($status['SubCode'])
            ? []
            : [new StatusCode(SAMLAnyURIValue::fromString($status['SubCode']))];
        $message = isset($status['Message']) && $status['Message'] !== ''
            ? new StatusMessage(SAMLStringValue::fromString($status['Message']))
            : null;

        return new Status(
            new StatusCode(SAMLAnyURIValue::fromString($status['Code'] ?? Constants::STATUS_SUCCESS), $subCodes),
            $message
        );
    }

    /**
     * @param string $return
     * @return $this
     */
    public function setReturn($return)
    {
        $this->return = $return;
        return $this;
    }

    /**
     * @return string
     */
    public function getReturn()
    {
        return $this->return;
    }

    /**
     * @param string $collabPersonId
     * @return $this
     */
    public function setCollabPersonId($collabPersonId)
    {
        $this->collabPersonId = $collabPersonId;
        return $this;
    }

    /**
     * @return string
     */
    public function getCollabPersonId()
    {
        return $this->collabPersonId;
    }

    public function setOriginalNameId(?NameID $originalNameId): EngineBlock_Saml2_ResponseAnnotationDecorator
    {
        $this->originalNameId = $originalNameId;
        return $this;
    }

    public function getOriginalNameId(): ?NameID
    {
        return $this->originalNameId;
    }

    public function setCustomNameId(NameID $customNameId): EngineBlock_Saml2_ResponseAnnotationDecorator
    {
        $this->customNameId = $customNameId;
        return $this;
    }

    public function getCustomNameId(): ?NameID
    {
        return $this->customNameId;
    }

    /**
     * @param string $intendedNameId
     * @return $this
     */
    public function setIntendedNameId($intendedNameId)
    {
        $this->intendedNameId = $intendedNameId;
        return $this;
    }

    /**
     * @return string
     */
    public function getIntendedNameId()
    {
        return $this->intendedNameId;
    }

    public function setPdpRequestedLoas(array $pdpLoas): EngineBlock_Saml2_ResponseAnnotationDecorator
    {
        $this->pdpRequestedLoas = $pdpLoas;
        return $this;
    }

    public function getPdpRequestedLoas(): array
    {
        return $this->pdpRequestedLoas;
    }

    /**
     * @param string $originalBinding
     * @return $this
     */
    public function setOriginalBinding($originalBinding)
    {
        $this->originalBinding = $originalBinding;
        return $this;
    }

    /**
     * @return string
     */
    public function getOriginalBinding()
    {
        return $this->originalBinding;
    }

    /**
     * @param string $originalIssuer
     * @return $this
     */
    public function setOriginalIssuer($originalIssuer)
    {
        $this->originalIssuer = $originalIssuer;
        return $this;
    }

    /**
     * @return string
     */
    public function getOriginalIssuer()
    {
        return $this->originalIssuer;
    }

    /**
     * @return $this
     */
    public function setOriginalResponse(EngineBlock_Saml2_ResponseAnnotationDecorator $originalResponse)
    {
        $this->originalResponse = $originalResponse;
        return $this;
    }

    /**
     * @return EngineBlock_Saml2_ResponseAnnotationDecorator
     */
    public function getOriginalResponse()
    {
        return $this->originalResponse;
    }

    public function isTransparentErrorResponse(): bool
    {
        return $this->isTransparentErrorResponse;
    }

    public function setIsTransparentErrorResponse(bool $isTransparentErrorResponse): void
    {
        $this->isTransparentErrorResponse = $isTransparentErrorResponse;
    }

    public function setSramInterruptNonce(string $SramInterruptNonce): void
    {
        $this->SramInterruptNonce = $SramInterruptNonce;
    }

    public function getSramInterruptNonce(): string
    {
        return $this->SramInterruptNonce;
    }

    #[Override]
    public function assertRestored(): void
    {
        parent::assertRestored();
        $this->originalResponse?->assertRestored();
    }

    public function __serialize(): array
    {
        return $this->serializeMessageState() + [
            'return' => $this->return,
            'originalIssuer' => $this->originalIssuer,
            'originalNameId' => Saml2Value::nameIdToXml($this->originalNameId),
            'originalBinding' => $this->originalBinding,
            'originalResponse' => $this->originalResponse,
            'collabPersonId' => $this->collabPersonId,
            'customNameId' => Saml2Value::nameIdToXml($this->customNameId),
            'intendedNameId' => $this->intendedNameId,
            'pdpRequestedLoas' => $this->pdpRequestedLoas,
            'isTransparentErrorResponse' => $this->isTransparentErrorResponse,
            'SramInterruptNonce' => $this->SramInterruptNonce,
            'attributeValueTypes' => $this->attributeValueTypes,
        ];
    }

    public function __unserialize(array $data): void
    {
        if (!$this->unserializeMessageState($data)) {
            return;
        }

        $this->return = $data['return'] ?? null;
        $this->originalIssuer = $data['originalIssuer'] ?? null;
        $this->originalBinding = $data['originalBinding'] ?? null;
        $this->originalResponse = $data['originalResponse'] ?? null;
        $this->collabPersonId = $data['collabPersonId'] ?? null;
        $this->intendedNameId = $data['intendedNameId'] ?? null;
        $this->pdpRequestedLoas = $data['pdpRequestedLoas'] ?? [];
        $this->isTransparentErrorResponse = (bool) ($data['isTransparentErrorResponse'] ?? false);
        $this->SramInterruptNonce = (string) ($data['SramInterruptNonce'] ?? '');
        $this->attributeValueTypes = (array) ($data['attributeValueTypes'] ?? []);

        try {
            $this->originalNameId = Saml2Value::nameIdFromXml($data['originalNameId'] ?? null);
            $this->customNameId = Saml2Value::nameIdFromXml($data['customNameId'] ?? null);
        } catch (Throwable $e) {
            $this->markRestoreFailure($e);
        }
    }

    #[Override]
    protected function rebuild(array $changes): void
    {
        $this->sspMessage = MessageRebuilder::response($this->getSspMessage(), $changes);
    }

    #[Override]
    protected function restoreMessage(string $xml): AbstractMessage
    {
        return Response::fromXML(Saml2Value::documentElement($xml));
    }
}
