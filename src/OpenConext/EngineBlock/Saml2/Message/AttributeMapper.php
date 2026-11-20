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

use InvalidArgumentException;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\Attribute;
use SimpleSAML\SAML2\XML\saml\AttributeStatement;
use SimpleSAML\SAML2\XML\saml\AttributeValue;
use SimpleSAML\XML\AbstractElement;
use SimpleSAML\XMLSchema\Type\Interface\AbstractAnySimpleType;
use SimpleSAML\XMLSchema\Type\Interface\ValueTypeInterface;
use Stringable;

/**
 * Maps between saml2 v7 attribute statements and EngineBlock's flat attribute arrays.
 *
 * The flat format is the one EngineBlock filters, ARPs, manipulations and consent work on:
 * `array<string, list<string|NameID|AbstractElement>>`. Scalar values are their trimmed lexical value,
 * the EPTI keeps its NameID and other complex content keeps its element. On write, strings become
 * xs:string and integers xs:integer unless an explicit value type is given.
 *
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects) Maps the SAML and XML Schema value types at the protocol boundary.
 */
final class AttributeMapper
{
    /**
     * @return array<string, list<mixed>>
     */
    public static function toFlat(Assertion $assertion): array
    {
        $attributes = [];
        foreach ($assertion->getAttributeStatements() as $statement) {
            foreach ($statement->getAttributes() as $attribute) {
                $name = $attribute->getName()->getValue();
                $attributes[$name] ??= [];
                foreach ($attribute->getAttributeValues() as $attributeValue) {
                    $attributes[$name][] = self::toFlatValue($attributeValue->getValue());
                }
            }
        }

        return $attributes;
    }

    /**
     * The single NameFormat of all attributes, or unspecified when they differ (legacy semantics).
     */
    public static function nameFormat(Assertion $assertion): string
    {
        $nameFormat = null;
        foreach ($assertion->getAttributeStatements() as $statement) {
            foreach ($statement->getAttributes() as $attribute) {
                $format = $attribute->getNameFormat()?->getValue() ?? Constants::NAMEFORMAT_UNSPECIFIED;
                if ($nameFormat !== null && $nameFormat !== $format) {
                    return Constants::NAMEFORMAT_UNSPECIFIED;
                }
                $nameFormat = $format;
            }
        }

        return $nameFormat ?? Constants::NAMEFORMAT_UNSPECIFIED;
    }

    /**
     * @param array<string, list<mixed>> $attributes
     * @param array<string, string|list<string|null>|null> $valueTypes xsi:type per attribute or per value
     */
    public static function toStatement(array $attributes, string $nameFormat, array $valueTypes = []): ?AttributeStatement
    {
        if ($attributes === []) {
            return null;
        }

        $format = $nameFormat === Constants::NAMEFORMAT_UNSPECIFIED ? null : SAMLAnyURIValue::fromString($nameFormat);

        $result = [];
        foreach ($attributes as $name => $values) {
            $types = $valueTypes[$name] ?? null;
            if (is_array($types) && count($types) !== count($values)) {
                throw new InvalidArgumentException(
                    sprintf('Number of value types does not match the number of values of attribute "%s"', $name)
                );
            }

            $attributeValues = [];
            foreach (array_values((array) $values) as $index => $value) {
                $type = is_array($types) ? $types[$index] : $types;
                $attributeValues[] = self::toAttributeValue($value, $type);
            }

            $result[] = new Attribute(SAMLStringValue::fromString((string) $name), $format, null, $attributeValues);
        }

        return new AttributeStatement($result);
    }

    private static function toFlatValue(ValueTypeInterface|AbstractElement|null $value): mixed
    {
        if ($value === null) {
            return '';
        }
        // Like saml2 4.x every scalar is read as its trimmed lexical value, whatever its xsi:type
        if ($value instanceof ValueTypeInterface) {
            return trim($value->getValue());
        }

        return $value;
    }

    private static function toAttributeValue(mixed $value, ?string $type): AttributeValue
    {
        if ($value instanceof AttributeValue) {
            return $value;
        }
        if ($value === null) {
            return new AttributeValue(null);
        }
        if ($value instanceof AbstractElement || $value instanceof ValueTypeInterface) {
            return new AttributeValue($value);
        }
        if (!is_scalar($value) && !$value instanceof Stringable) {
            throw new InvalidArgumentException(sprintf('Unsupported attribute value of type "%s"', get_debug_type($value)));
        }

        return new AttributeValue(self::typedValue($value, $type));
    }

    private static function typedValue(mixed $value, ?string $type): ValueTypeInterface
    {
        if ($type === null || $type === '') {
            $type = is_int($value) ? 'xs:integer' : 'xs:string';
        }
        $value = (string) $value;

        $localName = str_contains($type, ':') ? substr($type, strpos($type, ':') + 1) : $type;
        if ($localName === 'string') {
            return TypedStringValue::fromString($value);
        }

        $class = 'SimpleSAML\\XMLSchema\\Type\\' . ucfirst($localName) . 'Value';
        if (class_exists($class) && is_subclass_of($class, AbstractAnySimpleType::class)) {
            return $class::fromString($value);
        }

        return TypedStringValue::fromString($value);
    }
}
