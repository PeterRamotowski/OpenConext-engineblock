<?php

/**
 * Copyright 2025 SURFnet B.V.
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

namespace OpenConext\EngineBlock\Stepup;

use Dom\Element;
use EngineBlock_Saml2_AuthnRequestAnnotationDecorator;
use OpenConext\EngineBlock\Saml2\Message\AttributeMapper;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\Extensions;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;

class StepupGsspUserAttributeExtension
{
    public const NS = 'urn:mace:surf.nl:stepup:gssp-extensions';

    /**
     * Add (or replace) the gssp:UserAttributes extension, keeping all other extensions of the request.
     *
     * @param string[] $userAttributes
     */
    public static function add(
        EngineBlock_Saml2_AuthnRequestAnnotationDecorator $request,
        Assertion $assertion,
        array $userAttributes
    ): void {
        $assertionAttributes = AttributeMapper::toFlat($assertion);
        $stepupUserAttributes = array_filter($assertionAttributes, function ($attributeKey) use ($userAttributes) {
            return in_array($attributeKey, $userAttributes);
        }, ARRAY_FILTER_USE_KEY);

        if (count($stepupUserAttributes) === 0) {
            return;
        }

        $dom = DOMDocumentFactory::create();
        $ce = $dom->createElementNS(self::NS, 'gssp:UserAttributes');
        $ce->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $ce->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xs', 'http://www.w3.org/2001/XMLSchema');
        $dom->appendChild($ce);

        $nameFormat = AttributeMapper::nameFormat($assertion);
        foreach ($stepupUserAttributes as $attributeKey => $attributeValues) {
            self::addAttribute($ce, $attributeKey, $nameFormat, $attributeValues);
        }

        $extensions = array_values(array_filter(
            $request->getExtensions()?->getElements() ?? [],
            static fn ($element) => !($element instanceof Chunk
                && $element->getNamespaceURI() === self::NS
                && $element->getLocalName() === 'UserAttributes')
        ));
        $extensions[] = new Chunk($ce);

        $request->setExtensions(new Extensions($extensions));
    }

    /**
     * @param array<string|mixed> $values Only scalar values can be sent to the Stepup Gateway
     */
    public static function addAttribute(Element $parent, string $name, string $format, array $values): void
    {
        $document = $parent->ownerDocument;
        $attrib = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Attribute');
        $attrib->setAttribute('NameFormat', $format);
        $attrib->setAttribute('Name', $name);

        foreach ($values as $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $attribValue = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeValue');
            $attribValue->textContent = (string) $value;
            $attribValue->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:type', 'xs:string');
            $attrib->appendChild($attribValue);
        }

        $parent->appendChild($attrib);
    }
}
