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

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\PrivateKeyAgentEncryptionBackend;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\PrivateKeyAgentSignatureBackend;
use Surfnet\SamlBundle\DependencyInjection\PrivateKeyAgentConfiguration;
use Surfnet\SamlBundle\PrivateKeyAgent\AgentOperation;
use Surfnet\SamlBundle\PrivateKeyAgent\AlgorithmRegistrar;
use Surfnet\SamlBundle\PrivateKeyAgent\ConfiguredTokenProvider;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;

/**
 * A stand-in Private Key Agent behind xml-security's real agent backends, wired from the
 * surfnet_saml.private_key_agent.keys that EngineBlock derives from its encryption_keys.
 *
 * It answers the agent HTTP API with locally held test keys and records every request, so tests observe agent
 * call counts, key names and algorithms without a network. Only one instance may be registered at a time.
 */
final class FakePrivateKeyAgent implements ClientInterface
{
    public const string BASE_URL = 'https://agent.example.org';

    private const array DIGEST_INFO_PREFIXES = [
        'rsa-pkcs1-v1_5-sha256' => '3031300d060960864801650304020105000420',
        'rsa-pkcs1-v1_5-sha384' => '3041300d060960864801650304020205000430',
        'rsa-pkcs1-v1_5-sha512' => '3051300d060960864801650304020305000440',
    ];

    /**
     * @var list<array{operation: string, key: string, algorithm: string}>
     */
    public array $requests = [];

    private ?int $failureStatus = null;
    private bool $unreachable = false;
    private ?AlgorithmRegistrar $registrar = null;

    /**
     * @param array<string, string> $privateKeyPems Private key PEM by agent key name
     */
    public function __construct(private readonly array $privateKeyPems)
    {
    }

    /**
     * @param array<string, array{certificate_file: string, token: string, operations: list<string>}> $keys
     *        surfnet_saml.private_key_agent.keys
     */
    public function register(array $keys): void
    {
        $keyMap = new KeyMap(
            array_map(
                static fn (array $key): array => [
                    'certificate_file' => $key['certificate_file'],
                    'operations' => $key['operations'],
                ],
                $keys
            ),
            []
        );
        $tokens = new ConfiguredTokenProvider(array_map(static fn (array $key): string => $key['token'], $keys));
        $factory = new Psr17Factory();

        $this->registrar = new AlgorithmRegistrar(
            fn () => new PrivateKeyAgentSignatureBackend(
                $this,
                $factory,
                $factory,
                self::BASE_URL,
                $tokens,
                $keyMap->resolverFor(AgentOperation::SIGN)
            ),
            fn () => new PrivateKeyAgentEncryptionBackend(
                $this,
                $factory,
                $factory,
                self::BASE_URL,
                $tokens,
                $keyMap->resolverFor(AgentOperation::DECRYPT)
            ),
            PrivateKeyAgentConfiguration::SUPPORTED_SIGNATURE_ALGORITHMS,
            PrivateKeyAgentConfiguration::SUPPORTED_KEY_TRANSPORT_ALGORITHMS,
        );
        $this->registrar->register();
    }

    public function unregister(): void
    {
        $this->registrar?->unregister();
        $this->registrar = null;
    }

    public function failWithStatus(int $status): void
    {
        $this->failureStatus = $status;
    }

    public function beUnreachable(): void
    {
        $this->unreachable = true;
    }

    /**
     * @return list<string> The agent key names of the recorded requests for an operation
     */
    public function keysUsedFor(string $operation): array
    {
        return array_values(array_map(
            static fn (array $request): string => $request['key'],
            array_filter($this->requests, static fn (array $request): bool => $request['operation'] === $operation)
        ));
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        if (preg_match('#^/v1/(sign|decrypt)/([A-Za-z0-9_-]+)$#', $request->getUri()->getPath(), $match) !== 1) {
            return $this->json(404, ['error' => 'not found']);
        }
        [, $operation, $keyName] = $match;
        $body = json_decode((string) $request->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $this->requests[] = ['operation' => $operation, 'key' => $keyName, 'algorithm' => $body['algorithm']];

        if ($this->unreachable) {
            throw new class ('connection refused') extends RuntimeException implements ClientExceptionInterface {
            };
        }
        if ($this->failureStatus !== null) {
            return $this->json($this->failureStatus, ['error' => 'failure']);
        }
        if (!str_starts_with($request->getHeaderLine('Authorization'), 'Bearer ')) {
            return $this->json(401, ['error' => 'unauthenticated']);
        }
        $privateKey = $this->privateKeyPems[$keyName] ?? null;
        if ($privateKey === null) {
            return $this->json(404, ['error' => 'unknown key']);
        }

        return $operation === AgentOperation::SIGN
            ? $this->sign($privateKey, $body['algorithm'], base64_decode($body['hash'], true))
            : $this->decrypt($privateKey, $body['algorithm'], base64_decode($body['encrypted_data'], true));
    }

    private function sign(string $privateKey, string $algorithm, string $hash): ResponseInterface
    {
        $prefix = self::DIGEST_INFO_PREFIXES[$algorithm] ?? null;
        if ($prefix === null || !openssl_private_encrypt(hex2bin($prefix) . $hash, $signature, $privateKey)) {
            return $this->json(400, ['error' => 'cannot sign']);
        }

        return $this->json(200, ['signature' => base64_encode($signature)]);
    }

    private function decrypt(string $privateKey, string $algorithm, string $ciphertext): ResponseInterface
    {
        if ($algorithm !== 'rsa-pkcs1-oaep-mgf1-sha1'
            || !openssl_private_decrypt($ciphertext, $plaintext, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)
        ) {
            return $this->json(400, ['error' => 'cannot decrypt']);
        }

        return $this->json(200, ['decrypted_data' => base64_encode($plaintext)]);
    }

    private function json(int $status, array $body): ResponseInterface
    {
        $factory = new Psr17Factory();

        return $factory->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($factory->createStream(json_encode($body, JSON_THROW_ON_ERROR)));
    }
}
