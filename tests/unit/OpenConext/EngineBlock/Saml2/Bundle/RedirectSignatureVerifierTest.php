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

use OpenConext\EngineBlock\Saml2\Bundle\Exception\UnsupportedSignatureAlgorithmException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresMethod;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Symfony\Component\Clock\MockClock;

#[RequiresMethod(ReceivedAuthnRequestQueryString::class, 'getSignedRequestPayload')]
class RedirectSignatureVerifierTest extends TestCase
{
    private const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    private const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    private const OPENSSL_DIGESTS = [
        self::RSA_SHA1 => 'sha1',
        self::RSA_SHA256 => 'sha256',
        self::RSA_SHA384 => 'sha384',
        self::RSA_SHA512 => 'sha512',
    ];

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
    public function aSignatureWithAnRsaSha2AlgorithmIsVerified(string $algorithm): void
    {
        $query = $this->signedQuery($algorithm, 'sp');

        self::assertTrue($this->verifier()->isSignedBy($query, [GeneratedKeyPair::named('sp')->certificate()]));
    }

    #[Test]
    public function theReceivedQueryBytesAreVerifiedWithoutReencoding(): void
    {
        // Re-encoding would turn %2f into %2F and invalidate the signature.
        $query = $this->signedQuery(self::RSA_SHA384, 'sp', 'RelayState=https%3a%2f%2fsp.example.com%2fpage');

        self::assertTrue($this->verifier()->isSignedBy($query, [GeneratedKeyPair::named('sp')->certificate()]));
    }

    #[Test]
    public function everyConfiguredCertificateIsTried(): void
    {
        $query = $this->signedQuery(self::RSA_SHA512, 'sp');
        $certificates = [GeneratedKeyPair::named('other')->certificate(), GeneratedKeyPair::named('sp')->certificate()];

        self::assertTrue($this->verifier()->isSignedBy($query, $certificates));
    }

    #[Test]
    public function aSignatureByAnUnconfiguredKeyIsNotAccepted(): void
    {
        $query = $this->signedQuery(self::RSA_SHA256, 'other');

        self::assertFalse($this->verifier()->isSignedBy($query, [GeneratedKeyPair::named('sp')->certificate()]));
    }

    #[Test]
    public function aRelayStateChangedAfterSigningIsNotAccepted(): void
    {
        $signed = $this->signedQueryString(self::RSA_SHA256, 'sp', 'RelayState=original');
        $query = ReceivedAuthnRequestQueryString::parse(str_replace('RelayState=original', 'RelayState=changed', $signed));

        self::assertFalse($this->verifier()->isSignedBy($query, [GeneratedKeyPair::named('sp')->certificate()]));
    }

    #[Test]
    public function anUnsignedQueryIsNotSigned(): void
    {
        $query = ReceivedAuthnRequestQueryString::parse('SAMLRequest=' . urlencode(base64_encode('request')));

        self::assertFalse($this->verifier()->isSignedBy($query, [GeneratedKeyPair::named('sp')->certificate()]));
    }

    #[Test]
    public function rsaSha1IsRejected(): void
    {
        $this->expectException(UnsupportedSignatureAlgorithmException::class);

        $this->verifier()->isSignedBy(
            $this->signedQuery(self::RSA_SHA1, 'sp'),
            [GeneratedKeyPair::named('sp')->certificate()]
        );
    }

    #[Test]
    public function aForbiddenSignatureMethodIsRejected(): void
    {
        $verifier = new RedirectSignatureVerifier(new NullLogger(), [self::RSA_SHA384]);

        self::assertFalse($verifier->supports(self::RSA_SHA384));
        $this->expectException(UnsupportedSignatureAlgorithmException::class);

        $verifier->isSignedBy($this->signedQuery(self::RSA_SHA384, 'sp'), [GeneratedKeyPair::named('sp')->certificate()]);
    }

    #[Test]
    public function aBlacklistedAlgorithmIsRejected(): void
    {
        $this->container->setBlacklistedAlgorithms([self::RSA_SHA512]);

        self::assertFalse($this->verifier()->supports(self::RSA_SHA512));
        $this->expectException(UnsupportedSignatureAlgorithmException::class);

        $this->verifier()->isSignedBy(
            $this->signedQuery(self::RSA_SHA512, 'sp'),
            [GeneratedKeyPair::named('sp')->certificate()]
        );
    }

    private function verifier(): RedirectSignatureVerifier
    {
        return new RedirectSignatureVerifier(new NullLogger());
    }

    private function signedQuery(string $algorithm, string $signer, ?string $relayState = null): ReceivedAuthnRequestQueryString
    {
        return ReceivedAuthnRequestQueryString::parse($this->signedQueryString($algorithm, $signer, $relayState));
    }

    private function signedQueryString(string $algorithm, string $signer, ?string $relayState = null): string
    {
        $request = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request"'
            . ' Version="2.0" IssueInstant="2026-11-04T12:00:00Z"/>';
        $signedBytes = 'SAMLRequest=' . urlencode(base64_encode(gzdeflate($request)))
            . ($relayState === null ? '' : '&' . $relayState)
            . '&SigAlg=' . urlencode($algorithm);

        openssl_sign(
            $signedBytes,
            $signature,
            GeneratedKeyPair::named($signer)->privateKeyPem(),
            self::OPENSSL_DIGESTS[$algorithm]
        );

        return $signedBytes . '&Signature=' . urlencode(base64_encode($signature));
    }
}
