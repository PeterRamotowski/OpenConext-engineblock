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
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\saml\Issuer;
use SimpleSAML\SAML2\XML\samlp\AbstractMessage;
use SimpleSAML\SAML2\XML\samlp\AbstractRequest;
use SimpleSAML\SAML2\XML\samlp\AbstractStatusResponse;
use SimpleSAML\SAML2\XML\samlp\Extensions;
use SimpleSAML\XMLSchema\Type\IDValue;

/**
 * EngineBlock adapter around an immutable saml2 v7 protocol message.
 *
 * The adapter carries EngineBlock's annotations and the transport state that is not part of the
 * protocol element (RelayState, delivery binding). Mutators rebuild the wrapped message.
 *
 * Serialized adapters carry a format marker. Stored state written by another release is never
 * decoded (D7): it is marked stale and restarts the flow through the session-lost feedback.
 */
abstract class EngineBlock_Saml2_MessageAnnotationDecorator
{
    const MESSAGE_TYPE_REQUEST = 'SAMLRequest';
    const MESSAGE_TYPE_RESPONSE = 'SAMLResponse';

    /**
     * Bump when the serialized shape of the adapters changes in an incompatible way.
     */
    const SERIALIZATION_FORMAT = 'engineblock-saml2-v7/1';

    /**
     * @var AbstractMessage
     */
    protected $sspMessage;

    /**
     * @var string|null
     */
    protected $deliverByBinding;

    protected ?string $relayState = null;

    private bool $stale = false;

    private ?Throwable $restoreFailure = null;

    public function getId(): string
    {
        return $this->getSspMessage()->getId()->getValue();
    }

    public function setId(string $id): static
    {
        $this->rebuild(['id' => IDValue::fromString($id)]);
        return $this;
    }

    public function getIssuer(): ?Issuer
    {
        return $this->getSspMessage()->getIssuer();
    }

    public function getIssuerValue(): ?string
    {
        return Saml2Value::issuerValue($this->getIssuer());
    }

    public function setIssuer(Issuer|string|null $issuer): static
    {
        $this->rebuild(['issuer' => is_string($issuer) ? Saml2Value::issuer($issuer) : $issuer]);
        return $this;
    }

    public function getDestination(): ?string
    {
        return $this->getSspMessage()->getDestination()?->getValue();
    }

    public function setDestination(?string $destination): static
    {
        $this->rebuild(['destination' => $destination === null ? null : SAMLAnyURIValue::fromString($destination)]);
        return $this;
    }

    public function getIssueInstant(): int
    {
        return Saml2Value::timestamp($this->getSspMessage()->getIssueInstant());
    }

    public function setIssueInstant(int $timestamp): static
    {
        $this->rebuild(['issueInstant' => Saml2Value::dateTime($timestamp)]);
        return $this;
    }

    public function getConsent(): ?string
    {
        return $this->getSspMessage()->getConsent()?->getValue();
    }

    public function setConsent(?string $consent): static
    {
        $this->rebuild(['consent' => $consent === null || $consent === '' ? null : SAMLAnyURIValue::fromString($consent)]);
        return $this;
    }

    public function getExtensions(): ?Extensions
    {
        $extensions = $this->getSspMessage()->getExtensions();
        return $extensions instanceof Extensions ? $extensions : null;
    }

    public function setExtensions(?Extensions $extensions): static
    {
        $this->rebuild(['extensions' => $extensions]);
        return $this;
    }

    /**
     * The RelayState travels next to the message in the binding; it is not part of the protocol element.
     */
    public function getRelayState(): ?string
    {
        return $this->relayState;
    }

    public function setRelayState(?string $relayState): static
    {
        $this->relayState = $relayState;
        return $this;
    }

    /**
     * Algorithm of the enveloped signature this message was received with, if any.
     */
    public function getSignatureMethod(): ?string
    {
        return $this->getSspMessage()
            ->getSignature()
            ?->getSignedInfo()
            ->getSignatureMethod()
            ->getAlgorithm()
            ->getValue();
    }

    /**
     * @return AbstractMessage
     */
    public function getSspMessage()
    {
        $this->assertRestored();
        return $this->sspMessage;
    }

    /**
     * The XML of the message: the received XML for parsed (signed) messages, unsigned XML otherwise.
     */
    public function toXml(): string
    {
        return Saml2Value::toXmlString($this->getSspMessage()->toXML());
    }

    /**
     * @param string|null $deliverByBinding
     */
    public function setDeliverByBinding($deliverByBinding)
    {
        $this->deliverByBinding = $deliverByBinding;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getDeliverByBinding()
    {
        return $this->deliverByBinding;
    }

    /**
     * @return string
     * @throws RuntimeException
     */
    public function getMessageType()
    {
        $message = $this->getSspMessage();
        if ($message instanceof AbstractRequest) {
            return self::MESSAGE_TYPE_REQUEST;
        }
        if ($message instanceof AbstractStatusResponse) {
            return self::MESSAGE_TYPE_RESPONSE;
        }

        throw new RuntimeException('Unknown message type?!');
    }

    /**
     * Whether this adapter was restored from serialized state that cannot be used in this release.
     */
    public function isRestoredFromForeignState(): bool
    {
        return $this->stale;
    }

    /**
     * Guard for stored state: stale state from another release restarts the flow (session lost),
     * stored state that fails to decode maps to the invalid-response feedback with its cause.
     *
     * @throws EngineBlock_Corto_Module_Services_SessionLostException
     * @throws EngineBlock_Corto_Module_Bindings_VerificationException
     */
    public function assertRestored(): void
    {
        if ($this->stale) {
            throw new EngineBlock_Corto_Module_Services_SessionLostException(
                'Stored SAML message state was not written by this release, the authentication must be restarted'
            );
        }

        if ($this->restoreFailure !== null) {
            $cause = $this->restoreFailure instanceof Exception
                ? $this->restoreFailure
                : new RuntimeException($this->restoreFailure->getMessage(), 0, $this->restoreFailure);

            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                sprintf('Unable to decode the stored SAML message: %s', $this->restoreFailure->getMessage()),
                EngineBlock_Exception::CODE_NOTICE,
                $cause
            );
        }
    }

    /**
     * Replace the wrapped message by a rebuilt copy with the given changed fields.
     */
    abstract protected function rebuild(array $changes): void;

    /**
     * Parse the stored message XML.
     */
    abstract protected function restoreMessage(string $xml): AbstractMessage;

    protected function serializeMessageState(): array
    {
        if ($this->stale || $this->restoreFailure !== null) {
            return ['_format' => null];
        }

        return [
            '_format' => self::SERIALIZATION_FORMAT,
            '_serializableSspMessageXml' => $this->toXml(),
            '_serializableRelayState' => $this->relayState,
            'deliverByBinding' => $this->deliverByBinding,
        ];
    }

    /**
     * Restore the message state. Returns false when the state cannot be used by this release.
     */
    protected function unserializeMessageState(array $data): bool
    {
        if (($data['_format'] ?? null) !== self::SERIALIZATION_FORMAT) {
            $this->stale = true;
            return false;
        }

        $this->relayState = $data['_serializableRelayState'] ?? null;
        $this->deliverByBinding = $data['deliverByBinding'] ?? null;

        try {
            $this->sspMessage = $this->restoreMessage((string) ($data['_serializableSspMessageXml'] ?? ''));
        } catch (Throwable $e) {
            $this->markRestoreFailure($e);
            return false;
        }

        return true;
    }

    protected function markRestoreFailure(Throwable $failure): void
    {
        $this->restoreFailure ??= $failure;
    }

    /**
     * Dump a string representation of this annotated message used for debugging.
     *
     * @return string
     */
    public function __toString()
    {
        $vars = get_object_vars($this);
        unset($vars['stale'], $vars['restoreFailure']);
        $vars['sspMessage'] = $this->sspMessage instanceof AbstractMessage ? $this->toXml() : null;

        foreach ($vars as $name => $value) {
            if ($value instanceof self) {
                $vars[$name] = (string) $value;
            } elseif ($value instanceof \SimpleSAML\XML\AbstractElement) {
                $vars[$name] = Saml2Value::toXmlString($value);
            }
        }

        return json_encode($vars);
    }
}
