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

use SimpleSAML\XMLSchema\Type\Interface\AbstractAnySimpleType;

/**
 * An xs:string attribute value that is serialized with an explicit xsi:type="xs:string".
 *
 * saml2 v7 omits the xsi:type for its own StringValue, whereas EngineBlock has always emitted
 * xsi:type="xs:string" for string attribute values. Service providers and tests rely on that.
 */
final class TypedStringValue extends AbstractAnySimpleType
{
    public const string SCHEMA_TYPE = 'string';

    protected function validateValue(string $value): void
    {
    }
}
