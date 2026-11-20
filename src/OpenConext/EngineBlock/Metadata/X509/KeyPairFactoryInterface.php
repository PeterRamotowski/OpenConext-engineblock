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

namespace OpenConext\EngineBlock\Metadata\X509;

use OpenConext\EngineBlockBundle\Exception\UnknownKeyIdException;

/**
 * Selects EngineBlock's own key pairs by key ID for metadata and certificate endpoints.
 */
interface KeyPairFactoryInterface
{
    /**
     * @param string|null $identifier The key ID; null selects the default key pair.
     * @throws UnknownKeyIdException
     */
    public function buildFromIdentifier(?string $identifier): X509KeyPair;

    /**
     * @return array<X509KeyPair>
     */
    public function buildAll(): array;
}
