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

use ArrayObject;
use LogicException;
use OpenConext\EngineBlock\Exception\RuntimeException;
use OpenConext\EngineBlock\Saml2\Bundle\Exception\UnsupportedSignatureAlgorithmException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresMethod;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\XMLSecurity\Alg\Signature\PrivateKeyAgentRSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Backend\EncryptionBackend;
use SimpleSAML\XMLSecurity\Backend\OpenSSL;
use SimpleSAML\XMLSecurity\Backend\SignatureBackend;
use SimpleSAML\XMLSecurity\Key\KeyInterface;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\PrivateKeyAgent\AlgorithmRegistrar;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Symfony\Component\Clock\MockClock;

#[RequiresMethod(AlgorithmRegistrar::class, 'register')]
class SignerFactoryTest extends TestCase
{
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    private const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    private BridgeContainer $container;
    private AbstractContainer $originalContainer;

    protected function setUp(): void
    {
        $this->originalContainer = ContainerSingleton::getInstance();
        $this->container = new BridgeContainer(new NullLogger(), new MockClock());
        ContainerSingleton::setContainer($this->container);
    }

    protected function tearDown(): void
    {
        ContainerSingleton::setContainer($this->originalContainer);
        AlgorithmRegistrar::reset();
    }

    public static function rsaSha2Algorithms(): array
    {
        return [
            'RSA-SHA256' => [self::RSA_SHA256],
            'RSA-SHA384' => [self::RSA_SHA384],
            'RSA-SHA512' => [self::RSA_SHA512],
        ];
    }

    #[Test]
    #[DataProvider('rsaSha2Algorithms')]
    public function aLocalKeySignsWithTheRequestedRsaSha2Algorithm(string $algorithm): void
    {
        $keyPair = GeneratedKeyPair::named('local');

        $signer = (new SignerFactory())->forLocalKey($keyPair->privateKey(), $algorithm);

        self::assertSame($algorithm, $signer->getAlgorithmId());
        self::assertTrue($this->verifies($algorithm, $keyPair->certificate(), $signer->sign('message'), 'message'));
    }

    #[Test]
    public function rsaSha256IsTheDefault(): void
    {
        $signer = (new SignerFactory())->forLocalKey(GeneratedKeyPair::named('local')->privateKey());

        self::assertSame(self::RSA_SHA256, $signer->getAlgorithmId());
    }

    public static function unsupportedAlgorithms(): array
    {
        return [
            'RSA-SHA1' => ['http://www.w3.org/2000/09/xmldsig#rsa-sha1'],
            'RSA-SHA224' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha224'],
            'HMAC-SHA256' => ['http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'],
            'unknown' => ['urn:example:unknown'],
        ];
    }

    #[Test]
    #[DataProvider('unsupportedAlgorithms')]
    public function algorithmsOutsideRsaSha2AreRejectedWithoutSubstitution(string $algorithm): void
    {
        $this->expectException(UnsupportedSignatureAlgorithmException::class);

        (new SignerFactory())->forLocalKey(GeneratedKeyPair::named('local')->privateKey(), $algorithm);
    }

    #[Test]
    public function theBundleBlacklistAppliesToSigning(): void
    {
        $this->container->setBlacklistedAlgorithms([self::RSA_SHA512]);

        $this->expectException(UnsupportedSignatureAlgorithmException::class);

        (new SignerFactory())->forLocalKey(GeneratedKeyPair::named('local')->privateKey(), self::RSA_SHA512);
    }

    #[Test]
    public function anAgentCertificateSignsThroughTheRegisteredAgent(): void
    {
        $keyPair = GeneratedKeyPair::named('agent');
        $signedWith = $this->registerAgent($keyPair->privateKey(), [self::RSA_SHA384]);

        $signer = (new SignerFactory())->forAgentCertificate($keyPair->certificate(), self::RSA_SHA384);
        $signature = $signer->sign('message');

        self::assertInstanceOf(PrivateKeyAgentRSA::class, $signer);
        self::assertCount(1, $signedWith);
        self::assertInstanceOf(X509Certificate::class, $signedWith[0]);
        self::assertTrue($this->verifies(self::RSA_SHA384, $keyPair->certificate(), $signature, 'message'));
    }

    #[Test]
    public function anAgentCertificateNeverFallsBackWhenNoAgentIsRegisteredForTheAlgorithm(): void
    {
        $keyPair = GeneratedKeyPair::named('agent');
        $this->registerAgent($keyPair->privateKey(), [self::RSA_SHA256]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('not registered');

        (new SignerFactory())->forAgentCertificate($keyPair->certificate(), self::RSA_SHA512);
    }

    /**
     * Registers a stand-in agent that signs with the given key and records each key it was asked to sign with.
     *
     * @param list<string> $algorithms
     * @return ArrayObject<int, KeyInterface>
     */
    private function registerAgent(PrivateKey $agentKey, array $algorithms): ArrayObject
    {
        $signedWith = new ArrayObject();
        $backend = new class ($agentKey, $signedWith) implements SignatureBackend {
            private string $digest = '';

            public function __construct(private readonly PrivateKey $agentKey, private readonly ArrayObject $signedWith)
            {
            }

            public function setDigestAlg(string $digest): void
            {
                $this->digest = $digest;
            }

            public function sign(KeyInterface $key, string $plaintext): string
            {
                $this->signedWith[] = $key;
                $openSsl = new OpenSSL();
                $openSsl->setDigestAlg($this->digest);

                return $openSsl->sign($this->agentKey, $plaintext);
            }

            public function verify(KeyInterface $key, string $plaintext, string $signature): bool
            {
                throw new LogicException('The agent does not verify signatures');
            }
        };

        (new AlgorithmRegistrar(
            static fn (): SignatureBackend => $backend,
            static fn (): EncryptionBackend => throw new LogicException('The agent does not decrypt in this test'),
            $algorithms,
            [],
        ))->register();

        return $signedWith;
    }

    private function verifies(string $algorithm, X509Certificate $certificate, string $signature, string $message): bool
    {
        return (new SignatureAlgorithmFactory())
            ->getAlgorithm($algorithm, $certificate->getPublicKey())
            ->verify($message, $signature);
    }
}
