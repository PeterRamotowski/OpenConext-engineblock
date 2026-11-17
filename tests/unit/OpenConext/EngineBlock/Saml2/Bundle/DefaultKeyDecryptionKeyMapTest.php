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

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Surfnet\SamlBundle\PrivateKeyAgent\AgentOperation;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;

class DefaultKeyDecryptionKeyMapTest extends TestCase
{
    #[Test]
    public function onlyTheDefaultAgentCertificateMayDecrypt(): void
    {
        $keyMap = DefaultKeyDecryptionKeyMap::create([
            'rollover' => self::agentKey('rollover', ['sign']),
            'default' => self::agentKey('default', ['sign', 'decrypt']),
        ]);

        self::assertSame([self::fingerprint('default')], $this->decryptionFingerprints($keyMap));
        self::assertSame([], $keyMap->certificatesFor(AgentOperation::SIGN));
    }

    #[Test]
    public function replacingTheDefaultKeyMovesTheScopeInsteadOfWideningIt(): void
    {
        $keyMap = DefaultKeyDecryptionKeyMap::create([
            'default' => self::agentKey('rollover', ['sign', 'decrypt']),
            'previous' => self::agentKey('default', ['sign']),
        ]);

        self::assertSame([self::fingerprint('rollover')], $this->decryptionFingerprints($keyMap));
    }

    #[Test]
    public function aLocalDefaultKeyOrADefaultKeyWithoutDecryptHasNoAgentCandidates(): void
    {
        $local = DefaultKeyDecryptionKeyMap::create([
            'default' => ['publicFile' => '/keys/default.crt', 'privateFile' => '/keys/default.pem'],
            'rollover' => self::agentKey('rollover', ['sign']),
        ]);
        $signOnly = DefaultKeyDecryptionKeyMap::create(['default' => self::agentKey('default', ['sign'])]);

        self::assertSame([], $local->certificatesFor(AgentOperation::DECRYPT));
        self::assertSame([], $signOnly->certificatesFor(AgentOperation::DECRYPT));
    }

    private function decryptionFingerprints(KeyMap $keyMap): array
    {
        return array_map(KeyMap::fingerprintOf(...), $keyMap->certificatesFor(AgentOperation::DECRYPT));
    }

    private static function fingerprint(string $name): string
    {
        return KeyMap::fingerprintOf(GeneratedKeyPair::named($name)->certificate());
    }

    private static function agentKey(string $name, array $operations): array
    {
        return [
            'backend' => 'agent',
            'publicFile' => GeneratedKeyPair::named($name)->certificateFile(),
            'agent' => ['key' => 'eb-' . $name, 'token' => 'token', 'operations' => $operations],
        ];
    }
}
