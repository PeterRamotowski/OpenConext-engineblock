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

namespace OpenConext\EngineBlock\Saml2\Message;

use DateTimeImmutable;
use Dom\Element;
use Dom\XMLDocument;
use RuntimeException;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLDateTimeValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\Issuer;
use SimpleSAML\SAML2\XML\saml\NameID;
use SimpleSAML\XML\AbstractElement;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSchema\Type\Interface\ValueTypeInterface;

/**
 * Conversions between saml2 v7 typed values and the plain PHP values EngineBlock works with.
 */
final class Saml2Value
{
    public static function dateTime(int $timestamp): SAMLDateTimeValue
    {
        return SAMLDateTimeValue::fromDateTime(new DateTimeImmutable('@' . $timestamp));
    }

    public static function timestamp(?SAMLDateTimeValue $value): ?int
    {
        return $value?->toDateTime()->getTimestamp();
    }

    public static function string(?ValueTypeInterface $value): ?string
    {
        return $value?->getValue();
    }

    public static function issuer(string $entityId): Issuer
    {
        return new Issuer(SAMLStringValue::fromString($entityId));
    }

    public static function issuerValue(?Issuer $issuer): ?string
    {
        return $issuer?->getContent()->getValue();
    }

    public static function nameId(
        string $value,
        ?string $format = null,
        ?string $nameQualifier = null,
        ?string $spNameQualifier = null
    ): NameID {
        return new NameID(
            SAMLStringValue::fromString($value),
            $nameQualifier === null || $nameQualifier === '' ? null : SAMLStringValue::fromString($nameQualifier),
            $spNameQualifier === null || $spNameQualifier === '' ? null : SAMLStringValue::fromString($spNameQualifier),
            $format === null || $format === '' ? null : SAMLAnyURIValue::fromString($format),
        );
    }

    public static function nameIdValue(?NameID $nameId): ?string
    {
        return $nameId?->getContent()->getValue();
    }

    public static function nameIdFormat(?NameID $nameId): ?string
    {
        return $nameId?->getFormat()?->getValue();
    }

    /**
     * Serialize an element as a standalone XML string (explicit DOM boundary).
     */
    public static function toXmlString(AbstractElement|Element $element): string
    {
        $dom = $element instanceof Element ? $element : $element->toXML();
        $document = $dom->ownerDocument;
        $xml = $document instanceof XMLDocument ? $document->saveXml($dom) : false;
        if (!is_string($xml) || $xml === '') {
            throw new RuntimeException(sprintf('Unable to serialize "%s" to XML', $dom->localName));
        }

        return $xml;
    }

    public static function documentElement(string $xml): Element
    {
        $element = DOMDocumentFactory::fromString($xml)->documentElement;
        if (!$element instanceof Element) {
            throw new RuntimeException('XML document has no document element');
        }

        return $element;
    }

    public static function nameIdToXml(?NameID $nameId): ?string
    {
        return $nameId === null ? null : self::toXmlString($nameId);
    }

    public static function nameIdFromXml(?string $xml): ?NameID
    {
        return $xml === null ? null : NameID::fromXML(self::documentElement($xml));
    }
}
