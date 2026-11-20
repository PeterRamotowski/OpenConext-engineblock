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

namespace OpenConext\EngineBlock\Saml2\Bundle;

use SimpleSAML\XMLSecurity\Exception\PrivateKeyAgentExceptionInterface;
use Throwable;

/**
 * Redacted diagnostics for Private Key Agent failures.
 *
 * Callers replace the failure with an EngineBlock exception that does not chain it, so neither its previous
 * exceptions nor stack trace arguments reach the logs or feedback pages. Only the agent exception's class and its
 * fixed message (for example the HTTP status) are kept; xml-security never quotes tokens or responses in them.
 */
final class PrivateKeyAgentFailure
{
    public static function find(Throwable $throwable): ?PrivateKeyAgentExceptionInterface
    {
        for ($current = $throwable; $current !== null; $current = $current->getPrevious()) {
            if ($current instanceof PrivateKeyAgentExceptionInterface) {
                return $current;
            }
        }

        return null;
    }

    public static function describe(PrivateKeyAgentExceptionInterface $failure): string
    {
        $class = $failure::class;
        $message = $failure instanceof Throwable ? $failure->getMessage() : '';

        return sprintf('%s: %s', substr($class, (int) strrpos($class, '\\') + 1), $message);
    }
}
