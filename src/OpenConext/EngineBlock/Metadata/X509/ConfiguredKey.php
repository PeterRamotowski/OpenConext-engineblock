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

use SensitiveParameter;

/**
 * One validated entry of the encryption_keys parameter.
 *
 * A local key has a private key file; an agent key has none and names the Private Key Agent key that holds its
 * private key. Nothing is read from disk here, so the configuration can be validated during cache warmup.
 */
final readonly class ConfiguredKey
{
    public const string BACKEND_LOCAL = 'local';
    public const string BACKEND_AGENT = 'agent';

    public const string OPERATION_SIGN = 'sign';
    public const string OPERATION_DECRYPT = 'decrypt';

    /**
     * @param list<string> $agentOperations
     */
    private function __construct(
        public string $keyId,
        public string $publicFile,
        public ?string $privateFile,
        public ?string $agentKeyName,
        #[SensitiveParameter]
        private ?string $agentToken,
        public array $agentOperations,
    ) {
    }

    public static function local(string $keyId, string $publicFile, string $privateFile): self
    {
        return new self($keyId, $publicFile, $privateFile, null, null, []);
    }

    /**
     * @param list<string> $operations
     */
    public static function agent(
        string $keyId,
        string $publicFile,
        string $agentKeyName,
        #[SensitiveParameter]
        ?string $agentToken,
        array $operations,
    ): self {
        return new self($keyId, $publicFile, null, $agentKeyName, $agentToken, $operations);
    }

    public function usesPrivateKeyAgent(): bool
    {
        return $this->agentKeyName !== null;
    }

    /**
     * Null when read from the compiled encryption_keys parameter, from which tokens are removed.
     */
    public function agentToken(): ?string
    {
        return $this->agentToken;
    }

    public function mayDecrypt(): bool
    {
        return in_array(self::OPERATION_DECRYPT, $this->agentOperations, true);
    }
}
