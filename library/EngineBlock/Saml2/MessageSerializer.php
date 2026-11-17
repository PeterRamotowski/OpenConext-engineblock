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
use SimpleSAML\SAML2\XML\samlp\AbstractMessage;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XML\DOMDocumentFactory;

/**
 * Explicit DOM boundary between SAML protocol messages and their XML.
 */
class EngineBlock_Saml2_MessageSerializer
{
    private const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /**
     * The XML of the message. A message with a signer configured is signed by saml2 v7 on toXML().
     */
    public function serialize(AbstractMessage $samlMessage): string
    {
        return Saml2Value::toXmlString($samlMessage->toXML());
    }

    /**
     * @param string $samlMessageXml
     * @param class-string<AuthnRequest|Response> $class
     * @return AuthnRequest|Response
     * @throws EngineBlock_Corto_Module_Bindings_VerificationException when the XML is not a valid message
     * @throws EngineBlock_Exception for an unsupported message class
     */
    public function deserialize($samlMessageXml, $class)
    {
        $elementName = $this->getElementForClass($class);

        try {
            $document = DOMDocumentFactory::fromString((string) $samlMessageXml);
            $messageDomElement = $document->getElementsByTagNameNS(self::NS_SAMLP, $elementName)->item(0);
            if ($messageDomElement === null) {
                throw new RuntimeException(sprintf('No samlp:%s element found', $elementName));
            }

            return $class::fromXML($messageDomElement);
        } catch (Throwable $e) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                sprintf('Unable to parse the SAML %s: %s', $elementName, $e->getMessage()),
                EngineBlock_Exception::CODE_NOTICE,
                $e instanceof Exception ? $e : new RuntimeException($e->getMessage(), 0, $e)
            );
        }
    }

    /**
     * @param string $class
     * @return string
     * @throws EngineBlock_Exception
     */
    private function getElementForClass($class)
    {
        $mapping = array(
            AuthnRequest::class => 'AuthnRequest',
            Response::class => 'Response'
        );

        if (!isset($mapping[$class])) {
            throw new EngineBlock_Exception(sprintf('Unknown message type "%s" for deserialization', $class));
        }

        return $mapping[$class];
    }
}
