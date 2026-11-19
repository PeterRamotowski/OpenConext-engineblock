<?php

/**
 * Copyright 2010 SURFnet B.V.
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

use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use OpenConext\EngineBlock\Metadata\Entity\IdentityProvider;
use OpenConext\EngineBlock\Metadata\Entity\ServiceProvider;
use OpenConext\EngineBlock\Metadata\X509\X509CertificateFactory;
use OpenConext\EngineBlock\Metadata\X509\X509CertificateLazyProxy;
use OpenConext\EngineBlock\Request\CorrelationIdServiceInterface;
use OpenConext\EngineBlock\Request\CurrentCorrelationId;
use OpenConext\EngineBlock\Service\CookieService;
use OpenConext\EngineBlock\Service\FeedbackInfoCollectorInterface;
use OpenConext\EngineBlock\Service\FeedbackStateHelperInterface;
use OpenConext\EngineBlock\Service\MfaHelperInterface;
use OpenConext\EngineBlock\Service\TimeProvider\TimeProvider;
use OpenConext\EngineBlock\Service\Wayf\RememberedIdpCookie;
use OpenConext\EngineBlockBridge\Logger\LoginLogger;
use OpenConext\EngineBlockBundle\Bridge\DiContainerRuntime;
use OpenConext\EngineBlockBundle\Service\WayfRenderer;
use OpenConext\EngineBlock\Metadata\MetadataRepository\InMemoryMetadataRepository;
use OpenConext\EngineBlock\Metadata\X509\EncryptionKeysConfiguration;
use OpenConext\EngineBlock\Saml2\Bundle\DefaultKeyDecryptionKeyMap;
use OpenConext\EngineBlock\Saml2\Bundle\FakePrivateKeyAgent;
use OpenConext\EngineBlock\Saml2\Bundle\GeneratedKeyPair;
use OpenConext\EngineBlock\Saml2\Bundle\PolicyCheckingAssertionDecrypter;
use OpenConext\EngineBlock\Saml2\Bundle\ResponseEnvelopeVerifier;
use OpenConext\EngineBlock\Saml2\Bundle\SamlBundleConfiguration;
use OpenConext\EngineBlock\Saml2\Bundle\VerifiedResponseProcessor;
use OpenConext\EngineBlockBundle\Exception\ResponseProcessingFailedException;
use OpenConext\EngineBlockBundle\Configuration\FeatureConfiguration;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\XmlSecurity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Assertion\Validation\ConstraintValidator\NotBefore;
use SimpleSAML\SAML2\Assertion\Validation\ConstraintValidator\NotOnOrAfter;
use SimpleSAML\SAML2\Assertion\Validation\Result;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as XmlSecurityConstants;
use Surfnet\SamlBundle\PrivateKeyAgent\AlgorithmRegistrar;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Surfnet\SamlBundle\SAML2\Response\AgentAssertionDecrypter;
use Surfnet\SamlBundle\SAML2\Response\LocalAssertionDecrypter;
use Surfnet\SamlBundle\SAML2\Response\ResponseProcessor;
use Symfony\Component\Clock\MockClock;

/**
 * @todo test all other functionalities of Bindings, currently tests a small part of redirection
 */
class EngineBlock_Test_Corto_Module_BindingsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * @var EngineBlock_Corto_Module_Bindings
     */
    private $bindings;

    /**
     * @var EngineBlock_Corto_ProxyServer
     */
    private $proxyServer;

    private const SP_ENTITY_ID = 'https://sp.example.edu/metadata';
    private const IDP_ENTITY_ID = 'https://idp.example.edu/metadata';
    private const EB_SP_ENTITY_ID = 'https://engine.example.org/authentication/sp/metadata';
    private const ACS = 'https://engine.example.org/authentication/sp/consume-assertion';
    private const REQUEST_ID = '_request';
    private const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    private const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    private const NAMEID_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

    private ?AbstractContainer $originalSamlContainer = null;

    private $originalHttpRequest;

    private $originalDiContainer;

    private $mfaHelper;

    public function setUp(): void
    {
        $this->proxyServer = Phake::mock('EngineBlock_Corto_ProxyServer');
        Phake::when($this->proxyServer)->getSigningCertificates(false)->thenReturn(
            new EngineBlock_X509_KeyPair(
                new EngineBlock_X509_Certificate(openssl_x509_read(file_get_contents(__DIR__.'/test.pem.crt'))),
                new EngineBlock_X509_PrivateKey(__DIR__.'/test.pem.key')
            )
        );
        Phake::when($this->proxyServer)->getSigningCertificates(true)->thenReturn(
            new EngineBlock_X509_KeyPair(
                new EngineBlock_X509_Certificate(openssl_x509_read(file_get_contents(__DIR__.'/test.pem.crt'))),
                new EngineBlock_X509_PrivateKey(__DIR__.'/test.pem.key')
            )
        );
        Phake::when($this->proxyServer)->getConfig('WantsAuthnRequestsSigned')->thenReturn(false);
        Phake::when($this->proxyServer)->getConfig('forbiddenSignatureMethods')->thenReturn([]);
        Phake::when($this->proxyServer)->getLogger()->thenReturn(new NullLogger());

        $this->originalSamlContainer = ContainerSingleton::getInstance();
        ContainerSingleton::setContainer(new BridgeContainer(new NullLogger(), new MockClock('2026-11-04T12:00:00Z')));
        $this->originalHttpRequest = EngineBlock_ApplicationSingleton::getInstance()->getHttpRequest();
        $this->originalDiContainer = EngineBlock_ApplicationSingleton::getInstance()->getDiContainer();

        $this->installRuntime($this->createStub(Twig\Environment::class));

        $this->bindings = new EngineBlock_Corto_Module_Bindings($this->proxyServer);
    }

    protected function tearDown(): void
    {
        AlgorithmRegistrar::reset();
        ContainerSingleton::setContainer($this->originalSamlContainer);
        EngineBlock_ApplicationSingleton::getInstance()->setHttpRequest($this->originalHttpRequest);
        $this->setDiContainer($this->originalDiContainer);
    }

    public function testResponseRedirectIsNotSupported()
    {
        $this->expectException(EngineBlock_Corto_Module_Bindings_UnsupportedBindingException::class);

        $response = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse();
        $response->setDeliverByBinding(Constants::BINDING_HTTP_REDIRECT);

        $remoteEntity = new ServiceProvider('https://sp.example.edu');
        $this->bindings->send($response, $remoteEntity);
    }

    /**
     * We specifically test for some error / validation messages to have a certain value,
     * and throw a custom exception if that is the case. For example we did this to show a
     * custom user facing error page when the received SAML Response contains an assertion
     * from the past or future.
     *
     * This test simply verifies if the error message that is yielded from the SAML2 library
     * did not change, effectively changing behaviour of EB.
     *
     * Disclaimer, this is not a pure unit test in the sense it tests a specific feature of
     * Bindings. This however seemed the most logical place to put it.
     */
    public function test_saml2_library_error_messages_we_specifically_test_have_not_changed()
    {
        $result = new Result();

        (new NotBefore())->validate($this->parseAssertion($this->assertionXml(notBefore: '2286-11-20T17:46:40Z', notOnOrAfter: '2286-11-20T17:51:40Z')), $result);
        $this->assertEquals(
            'Received an assertion that is valid in the future. Check clock synchronization on IdP and SP.',
            $result->getErrors()[0]
        );

        (new NotOnOrAfter())->validate($this->parseAssertion($this->assertionXml(notBefore: '1970-01-01T00:00:00Z', notOnOrAfter: '1970-01-01T00:00:01Z')), $result);
        $this->assertEquals(
            'Received an assertion that has expired. Check clock synchronization on IdP and SP.',
            $result->getErrors()[1]
        );
    }

    /**
     * Provides a list of paths to response xml files and certificate files
     *
     * @return array
     */
    public function responseProvider()
    {
        $responseFiles = array();
        $certificateFiles = array();
        $responsesDir = TEST_RESOURCES_DIR.'/saml/responses';
        $defaultCertFile = $responsesDir.'/defaultCert';
        $responsesDirIterator = new DirectoryIterator($responsesDir);
        /** @var $responseFile DirectoryIterator */
        foreach ($responsesDirIterator as $responseFile) {
            if ($responseFile->isFile() && !$responseFile->isDot()) {
                $extension = substr($responseFile->getFilename(), -3);
                $fileNameWithoutExtension = substr($responseFile->getFilename(), 0, -4);

                if ($extension == 'cer' || $extension == 'pem') {
                    $certificateFiles[$fileNameWithoutExtension] = $responseFile->getRealPath();
                } elseif ($extension == 'xml') {
                    $responseFiles[$fileNameWithoutExtension] = $responseFile->getRealPath();

                    // Set default certificate, can be overridden by adding a certificate with the same name as the response
                    if (!isset($certificateFiles[$fileNameWithoutExtension])) {
                        $certificateFiles[$fileNameWithoutExtension] = $defaultCertFile;
                    }
                }
            }
        }

        return array_merge_recursive($responseFiles, $certificateFiles);
    }

    public function testAzureDomainHintIsAppendedToRedirectUrl()
    {
        $request = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['destination' => 'https://login.microsoftonline.com/tenant-id/saml2']);
        $request->setDeliverByBinding(Constants::BINDING_HTTP_REDIRECT);

        $idp = new IdentityProvider(
            entityId: 'https://idp.example.com',
            azureDomainHint: 'hartingcollege.nl'
        );

        $this->bindings->send($request, $idp);

        Phake::verify($this->proxyServer)->redirect(
            Phake::capture($redirectUrl),
            Phake::capture($capturedMessage)
        );

        $parsed = parse_url($redirectUrl);
        $this->assertArrayHasKey('query', $parsed, 'Redirect URL must have a query string');
        parse_str($parsed['query'], $params);
        $this->assertArrayHasKey('whr', $params, 'whr query parameter must be present');
        $this->assertSame('hartingcollege.nl', $params['whr']);
    }

    public function testAzureDomainHintIsNotAddedWhenNotConfigured()
    {
        $request = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['destination' => 'https://idp.example.com/sso']);
        $request->setDeliverByBinding(Constants::BINDING_HTTP_REDIRECT);

        $idp = new IdentityProvider('https://idp.example.com');

        $this->bindings->send($request, $idp);

        Phake::verify($this->proxyServer)->redirect(
            Phake::capture($redirectUrl),
            Phake::capture($capturedMessage)
        );

        $this->assertStringNotContainsString('whr=', $redirectUrl);
    }

    public function testAzureDomainHintWhrParamIsCorrectlyUrlEncoded()
    {
        $request = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['destination' => 'https://login.microsoftonline.com/tenant-id/saml2']);
        $request->setDeliverByBinding(Constants::BINDING_HTTP_REDIRECT);

        $idp = new IdentityProvider(
            entityId: 'https://idp.example.com',
            azureDomainHint: 'example.nl'
        );

        $this->bindings->send($request, $idp);

        Phake::verify($this->proxyServer)->redirect(
            Phake::capture($redirectUrl),
            Phake::capture($capturedMessage)
        );

        $parsed = parse_url($redirectUrl);
        $this->assertArrayHasKey('query', $parsed, 'Redirect URL must have a query string');
        parse_str($parsed['query'], $params);
        $this->assertArrayHasKey('whr', $params, 'whr query parameter must be present');
        $this->assertSame('example.nl', $params['whr']);
    }

    public function testHttpPostPassesRelayStateAndReturnAsTemplateVariablesWithoutHtml()
    {
        $twig = $this->createMock(Twig\Environment::class);
        $twig->expects($this->once())
            ->method('render')
            ->with(
                '@theme/Authentication/View/Proxy/form.html.twig',
                $this->callback(function (array $parameters) {
                    $this->assertSame('relay"state<>&', $parameters['relayState']);
                    $this->assertSame('https://engine.example.org/processed', $parameters['return']);
                    $this->assertArrayNotHasKey('xtra', $parameters);
                    $this->assertSame('SAMLResponse', $parameters['name']);
                    $this->assertSame(base64_encode(base64_decode($parameters['message'], true)), $parameters['message']);
                    return true;
                })
            )
            ->willReturn('rendered');

        $response = $this->createPostResponse();
        $response->setReturn('https://engine.example.org/processed');
        $response->setDeliverByBinding(Constants::BINDING_HTTP_POST);
        $response->setRelayState('relay"state<>&');

        $this->createBindingsWithTwig($twig)->send($response, new ServiceProvider('https://sp.example.edu'));

        Phake::verify($this->proxyServer)->sendOutput('rendered');
    }

    public function testHttpPostPassesNoRelayStateOrReturnWhenAbsent()
    {
        $twig = $this->createMock(Twig\Environment::class);
        $twig->expects($this->once())
            ->method('render')
            ->with(
                '@theme/Authentication/View/Proxy/form.html.twig',
                $this->callback(function (array $parameters) {
                    $this->assertNull($parameters['relayState']);
                    $this->assertNull($parameters['return']);
                    return true;
                })
            )
            ->willReturn('rendered');

        $response = $this->createPostResponse();
        $response->setReturn('  ');
        $response->setDeliverByBinding(Constants::BINDING_HTTP_POST);

        $this->createBindingsWithTwig($twig)->send($response, new ServiceProvider('https://sp.example.edu'));
    }

    public function testHttpPostEncodesAndRendersFalsyRelayState()
    {
        $loader = new Twig\Loader\FilesystemLoader();
        $loader->addPath(__DIR__ . '/../../../../../../theme/base/templates/modules', 'theme');
        $loader->addPath(__DIR__ . '/../../../../../../theme/base/templates/layouts', 'themeLayouts');
        $twig = new Twig\Environment($loader, ['strict_variables' => false]);
        $twig->addFunction(new Twig\TwigFunction('locale', static fn () => 'en'));
        $twig->addFilter(new Twig\TwigFilter('trans', static fn ($id) => $id));

        $response = $this->createPostResponse();
        $response->setDeliverByBinding(Constants::BINDING_HTTP_POST);
        $response->setRelayState('0');

        $this->createBindingsWithTwig($twig)->send($response, new ServiceProvider('https://sp.example.edu'));

        Phake::verify($this->proxyServer)->sendOutput(Phake::capture($html));
        $document = Dom\HTMLDocument::createFromString($html, LIBXML_NOERROR);
        $relayStates = $document->querySelectorAll('#ProcessForm input[name="RelayState"]');
        $this->assertCount(1, $relayStates);
        $this->assertSame('0', $relayStates->item(0)->getAttribute('value'));
    }

    #[DataProvider('redirectSigningProvider')]
    public function testRedirectRequestKeepsFalsyRelayState(bool $mustBeSigned)
    {
        $request = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(
            ['destination' => 'https://idp.example.com/sso', 'issuer' => self::EB_SP_ENTITY_ID],
            '0'
        );
        $request->setDeliverByBinding(Constants::BINDING_HTTP_REDIRECT);

        $this->bindings->send(
            $request,
            new IdentityProvider('https://idp.example.com', requestsMustBeSigned: $mustBeSigned, signatureMethod: self::RSA_SHA512)
        );

        Phake::verify($this->proxyServer)->redirect(Phake::capture($redirectUrl), Phake::capture($capturedMessage));
        $rawParameters = [];
        foreach (explode('&', parse_url($redirectUrl, PHP_URL_QUERY)) as $pair) {
            [$name, $value] = explode('=', $pair, 2);
            $rawParameters[$name] = $value;
        }
        $this->assertSame('0', rawurldecode($rawParameters['RelayState']));

        if (!$mustBeSigned) {
            $this->assertArrayNotHasKey('SigAlg', $rawParameters);
            $this->assertArrayNotHasKey('Signature', $rawParameters);
            return;
        }

        $this->assertSame(self::RSA_SHA512, rawurldecode($rawParameters['SigAlg']));
        $signedQuery = sprintf(
            'SAMLRequest=%s&RelayState=%s&SigAlg=%s',
            $rawParameters['SAMLRequest'],
            $rawParameters['RelayState'],
            $rawParameters['SigAlg']
        );
        $this->assertTrue(XmlSecurity::verifyRedirectSignature(
            $signedQuery,
            base64_decode(rawurldecode($rawParameters['Signature']), true),
            file_get_contents(__DIR__ . '/test.pem.crt'),
            self::RSA_SHA512
        ));
    }

    public static function redirectSigningProvider(): array
    {
        return ['unsigned' => [false], 'signed' => [true]];
    }

    /**
     * The assertion signature is checked in the final serialized Response: saml2 signs nested elements into a
     * detached document, so a signer set on the assertion alone would be lost when the Response is serialized.
     */
    #[DataProvider('outgoingResponseSignatureProvider')]
    public function testPostResponseCarriesVerifiableAssertionSignature(string $algorithm, bool $signResponse)
    {
        $twig = $this->createMock(Twig\Environment::class);
        $twig->expects($this->once())
            ->method('render')
            ->with('@theme/Authentication/View/Proxy/form.html.twig', $this->callback(function (array $parameters) use (&$message) {
                $message = $parameters['message'];
                return true;
            }))
            ->willReturn('rendered');

        $response = $this->createPostResponse();
        $response->setDeliverByBinding(Constants::BINDING_HTTP_POST);
        $this->createBindingsWithTwig($twig)->send(
            $response,
            new ServiceProvider('https://sp.example.edu', signatureMethod: $algorithm, signResponse: $signResponse)
        );

        $document = DOMDocumentFactory::fromString(base64_decode($message, true));
        $sentResponse = Response::fromXML($document->documentElement);
        $verifier = XmlSecurity::verifier(file_get_contents(__DIR__ . '/test.pem.crt'), $algorithm);

        $assertions = $sentResponse->getAssertions();
        $this->assertCount(1, $assertions);
        $this->assertTrue($assertions[0]->isSigned(), 'The assertion in the serialized Response must be signed');
        $this->assertSame(
            $algorithm,
            $assertions[0]->getSignature()->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue()
        );
        $verifiedAssertion = $assertions[0]->verify($verifier);
        $this->assertInstanceOf(Assertion::class, $verifiedAssertion);
        $this->assertSignatureFollowsIssuer($document->getElementsByTagNameNS(Constants::NS_SAML, 'Assertion')->item(0));

        $this->assertSame($signResponse, $sentResponse->isSigned());
        if ($signResponse) {
            $verifiedResponse = $sentResponse->verify($verifier);
            $this->assertInstanceOf(Response::class, $verifiedResponse);
            $this->assertSignatureFollowsIssuer($document->documentElement);
        }
    }

    public static function outgoingResponseSignatureProvider(): array
    {
        $cases = [];
        foreach (['sha256' => self::RSA_SHA256, 'sha384' => self::RSA_SHA384, 'sha512' => self::RSA_SHA512] as $name => $algorithm) {
            $cases["$name, assertion only"] = [$algorithm, false];
            $cases["$name, assertion and response"] = [$algorithm, true];
        }

        return $cases;
    }

    private function assertSignatureFollowsIssuer(Dom\Element $element): void
    {
        $issuer = $element->firstElementChild;
        $this->assertSame('Issuer', $issuer->localName);
        $this->assertSame('Signature', $issuer->nextElementSibling?->localName);
        $this->assertSame('http://www.w3.org/2000/09/xmldsig#', $issuer->nextElementSibling->namespaceURI);
    }

    private function installRuntime(Twig\Environment $twig): void
    {
        \EngineBlock_ApplicationSingleton::getInstance()->setDiContainerRuntime(new DiContainerRuntime(
            $twig,
            $this->createStub(WayfRenderer::class),
            $this->createStub(CorrelationIdServiceInterface::class),
            new CurrentCorrelationId(),
            $this->createStub(FeedbackStateHelperInterface::class),
            $this->createStub(FeedbackInfoCollectorInterface::class),
            $this->createStub(LoginLogger::class),
            new RememberedIdpCookie(
                $this->createStub(TimeProvider::class),
                $this->createStub(CookieService::class),
                7776000,
                16,
                'engine.example.org',
                '/',
                true,
            ),
        ));
    }

    private function createPostResponse(): EngineBlock_Saml2_ResponseAnnotationDecorator
    {
        return EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse(['destination' => 'https://sp.example.edu/acs']);
    }

    private function createBindingsWithTwig(Twig\Environment $twig): EngineBlock_Corto_Module_Bindings
    {
        $this->installRuntime($twig);

        Phake::when($this->proxyServer)->getLogger()->thenReturn($this->createStub(Psr\Log\LoggerInterface::class));

        return new EngineBlock_Corto_Module_Bindings($this->proxyServer);
    }

    public function testOldSpIssueInstantLogsWarningOnly()
    {
        $logger = $this->mockLogger();
        $logger->shouldReceive('warning')->once()->with(m::pattern('/is \d+ seconds \(more than 24 hours\) in the past/'));
        $logger->shouldNotReceive('notice');

        $this->checkIssueInstant(time() - 90000, 'SP', 'https://sp.example.edu');
    }

    public function testRecentSpIssueInstantLogsNoticeOnly()
    {
        $logger = $this->mockLogger();
        $logger->shouldReceive('notice')->once()->with(m::pattern('/clock synchronization issues/'));
        $logger->shouldNotReceive('warning');

        $this->checkIssueInstant(time() - 600, 'SP', 'https://sp.example.edu');
    }

    public function testOldIdpIssueInstantLogsGenericNoticeNotWarning()
    {
        $logger = $this->mockLogger();
        $logger->shouldReceive('notice')->once()->with(m::pattern('/clock synchronization issues/'));
        $logger->shouldNotReceive('warning');

        $this->checkIssueInstant(time() - 90000, 'IdP', 'https://idp.example.edu');
    }

    public function testFreshSpIssueInstantLogsNothing()
    {
        $logger = $this->mockLogger();
        $logger->shouldNotReceive('warning');
        $logger->shouldNotReceive('notice');

        $this->checkIssueInstant(time(), 'SP', 'https://sp.example.edu');
    }

    public function testMissingDestinationLogsNoticeWithIssuerAndSignaturePresence()
    {
        $logger = $this->mockLogger();
        $logger->shouldReceive('notice')->once()->with(
            'Received Response without Destination',
            ['issuer' => 'https://idp.example.edu', 'response_signed' => false]
        );

        $response = $this->responseXml(destination: null);

        $this->invokePrivate('logMissingDestination', $this->documentElement($response), 'https://idp.example.edu');
    }

    public function testPresentDestinationLogsNothing()
    {
        $logger = $this->mockLogger();
        $logger->shouldNotReceive('notice');

        $this->invokePrivate('logMissingDestination', $this->documentElement($this->responseXml()), 'https://idp.example.edu');
    }

    #[DataProvider('encryptedAssertionLayoutProvider')]
    public function testEncryptedAssertionLogsAlgorithmsAndKeyLayout(
        string $keyInfo,
        string $siblings,
        array $expectedKeyTransportAlgorithms,
        string $expectedKeyLayout
    ) {
        $logger = $this->mockLogger();
        $logger->shouldReceive('notice')->once()->with(
            'Received encrypted Assertion',
            [
                'issuer' => 'https://idp.example.edu',
                'content_encryption_algorithm' => 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
                'key_transport_algorithms' => $expectedKeyTransportAlgorithms,
                'key_layout' => $expectedKeyLayout,
            ]
        );

        $response = $this->responseXml(assertions: $this->assertionXml() . $this->encryptedAssertionXml($keyInfo, $siblings));

        $this->invokePrivate('logEncryptedAssertionLayouts', $this->documentElement($response), 'https://idp.example.edu');
    }

    public static function encryptedAssertionLayoutProvider(): array
    {
        $oaep = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
        $pkcs1 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

        return [
            'single key in KeyInfo' => [self::encryptedKey($oaep), '', [$oaep], 'single-key-in-key-info'],
            'multiple keys in KeyInfo' => [
                self::encryptedKey($oaep) . self::encryptedKey($pkcs1),
                '',
                [$oaep, $pkcs1],
                'multiple-keys-in-key-info',
            ],
            'RetrievalMethod to sibling key' => [self::retrievalMethod(), self::encryptedKey($oaep), [], 'retrieval-method'],
            'unreferenced sibling key' => ['', self::encryptedKey($oaep), [], 'no-key-in-key-info'],
        ];
    }

    public function testUnencryptedAssertionLogsNothing()
    {
        $logger = $this->mockLogger();
        $logger->shouldNotReceive('notice');

        $this->invokePrivate('logEncryptedAssertionLayouts', $this->documentElement($this->responseXml()), 'https://idp.example.edu');
    }

    public function testUnsignedPostRequestIsReceivedWithRelayStateAndTransientAllowCreateDropped()
    {
        $this->useServiceProvider();
        $this->postMessage('SAMLRequest', $this->authnRequestXml(nameIdPolicy: true), 'relay"state<>&');

        $request = $this->bindings->receiveRequest();

        $this->assertSame('relay"state<>&', $request->getRelayState());
        $this->assertSame(self::SP_ENTITY_ID, $request->getIssuerValue());
        $this->assertNull($request->getSspMessage()->getNameIdPolicy()->getAllowCreate());
        $this->assertFalse($request->wasSigned());
        Phake::verify($this->proxyServer)->setReceivedRequest($request);
    }

    public function testSignedPostRequestWithTransientAllowCreateIsNotRewritten()
    {
        $this->useServiceProvider();
        $signed = $this->signedAuthnRequestXml($this->authnRequestXml(nameIdPolicy: true), 'sp');
        $withAllowCreate = str_replace('<samlp:NameIDPolicy ', '<samlp:NameIDPolicy AllowCreate="true" ', $signed);
        $this->assertNotSame($signed, $withAllowCreate);
        $this->postMessage('SAMLRequest', $withAllowCreate);

        $this->expectException(EngineBlock_Corto_Module_Bindings_UnableToReceiveMessageException::class);

        $this->bindings->receiveRequest();
    }

    public function testAuthnRequestWithARelativeRequesterIdIsRejected(): void
    {
        $this->useServiceProvider();
        $requestXml = str_replace(
            '</samlp:AuthnRequest>',
            '<samlp:Scoping><samlp:RequesterID>unknown-sp</samlp:RequesterID></samlp:Scoping></samlp:AuthnRequest>',
            $this->authnRequestXml()
        );
        $this->postMessage('SAMLRequest', $requestXml);

        try {
            $this->bindings->receiveRequest();
            $this->fail('Expected the request to be rejected');
        } catch (EngineBlock_Corto_Module_Bindings_UnableToReceiveMessageException $exception) {
            $this->assertStringContainsString('unknown-sp', $exception->getMessage());
            Phake::verify($this->proxyServer, Phake::never())->setReceivedRequest(Phake::anyParameters());
        }
    }

    #[DataProvider('lookalikeDestinationProvider')]
    public function testRequestDestinationMustExactlyMatchTheSingleSignOnLocation(string $suffix, bool $replaceScheme)
    {
        $destination = $this->singleSignOnLocation() . $suffix;
        if ($replaceScheme) {
            $destination = str_starts_with($destination, 'https:')
                ? 'http:' . substr($destination, 6)
                : 'https:' . substr($destination, 5);
        }
        $this->useServiceProvider();
        $this->postMessage('SAMLRequest', $this->authnRequestXml(destination: $destination));

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);
        $this->expectExceptionMessage('does not match the single sign-on location');

        $this->bindings->receiveRequest();
    }

    public static function lookalikeDestinationProvider(): array
    {
        return [
            'trailing slash' => ['/', false],
            'longer path' => ['-other', false],
            'query' => ['?idp=1', false],
            'other scheme' => ['', true],
            'undispatched IdP hash' => ['/0123456789abcdef', false],
        ];
    }

    public function testRequestDestinationMayBeTheDispatchedIdpRoute()
    {
        $this->useServiceProvider();
        $this->postMessage('SAMLRequest', $this->authnRequestXml(destination: $this->singleSignOnLocation() . '/0123456789abcdef'));

        $request = $this->bindings->receiveRequest('0123456789abcdef');

        $this->assertSame($this->singleSignOnLocation() . '/0123456789abcdef', $request->getDestination());
    }

    public function testSignedPostRequestIsVerifiedWithAnyConfiguredCertificate()
    {
        $this->useServiceProvider(['other', 'sp'], requestsMustBeSigned: true);
        $this->postMessage('SAMLRequest', $this->signedAuthnRequestXml($this->authnRequestXml(), 'sp'), 'state');

        $request = $this->bindings->receiveRequest();

        $this->assertTrue($request->wasSigned());
        $this->assertSame('state', $request->getRelayState());
    }

    public function testSignedPostRequestFromAnUnconfiguredKeyIsRejected()
    {
        $this->useServiceProvider(['sp'], requestsMustBeSigned: true);
        $this->postMessage('SAMLRequest', $this->signedAuthnRequestXml($this->authnRequestXml(), 'other'));

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);
        $this->expectExceptionMessage('the signature could not be verified');

        $this->bindings->receiveRequest();
    }

    public function testRequiredPostRequestSignatureMustBePresent()
    {
        $this->useServiceProvider(['sp'], requestsMustBeSigned: true);
        $this->postMessage('SAMLRequest', $this->authnRequestXml());

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);
        $this->expectExceptionMessage('no signature found on message');

        $this->bindings->receiveRequest();
    }

    public function testSha1SignedPostRequestIsRejected()
    {
        $this->useServiceProvider(['sp'], requestsMustBeSigned: true);
        $this->postMessage('SAMLRequest', $this->signedAuthnRequestXml($this->authnRequestXml(), 'sp', self::RSA_SHA1));

        $this->expectException(EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException::class);

        $this->bindings->receiveRequest();
    }

    public function testSignedRequestWithoutDestinationIsRejected()
    {
        $this->useServiceProvider(['sp']);
        $this->postMessage('SAMLRequest', $this->signedAuthnRequestXml($this->authnRequestXml(destination: null), 'sp'));

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);
        $this->expectExceptionMessage('Signed AuthnRequest has no Destination');

        $this->bindings->receiveRequest();
    }

    public function testRedirectRequestSignatureIsVerifiedOverTheOriginalQueryBytes()
    {
        $this->useServiceProvider(['sp'], requestsMustBeSigned: true);
        $this->redirectMessage($this->signedRedirectQuery($this->authnRequestXml(), 'https://sp.example.edu/return?a=b', true));

        $request = $this->bindings->receiveRequest();

        $this->assertTrue($request->wasSigned());
        $this->assertSame('https://sp.example.edu/return?a=b', $request->getRelayState());
    }

    public function testRedirectRequestSignatureDoesNotCoverReencodedQueryBytes()
    {
        $this->useServiceProvider(['sp'], requestsMustBeSigned: true);
        $query = $this->signedRedirectQuery($this->authnRequestXml(), 'https://sp.example.edu/return?a=b', false);
        $this->redirectMessage(self::lowercasePercentEncoding($query));

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);
        $this->expectExceptionMessage('the signature could not be verified');

        $this->bindings->receiveRequest();
    }

    public function testForbiddenRedirectSignatureMethodIsRejected()
    {
        Phake::when($this->proxyServer)->getConfig('forbiddenSignatureMethods')->thenReturn([self::RSA_SHA256]);
        $this->useServiceProvider(['sp'], requestsMustBeSigned: true);
        $this->redirectMessage($this->signedRedirectQuery($this->authnRequestXml(), null, false));

        $this->expectException(EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException::class);

        $this->bindings->receiveRequest();
    }

    public function testRedirectResponseIsNotSupported()
    {
        $this->redirectMessage('SAMLResponse=' . urlencode(base64_encode(gzdeflate($this->responseXml()))));

        $this->expectException(EngineBlock_Corto_Module_Bindings_UnsupportedBindingException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testSignedResponseYieldsTheVerifiedEnvelopeAndValidatedAssertion()
    {
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->signedResponseXml($this->responseXml(), 'idp', self::RSA_SHA512), 'state');

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertSame('state', $response->getRelayState());
        $this->assertSame(self::RSA_SHA512, $response->getSignatureMethod());
        $this->assertNull($response->getAssertionSignatureMethod());
        $this->assertCount(1, $response->getAssertions());
        $this->assertSame('john-doe', $response->getNameIdValue());
        Phake::verify($this->proxyServer)->findRequestFromRequestId(self::REQUEST_ID);
        Phake::verify($this->proxyServer)->consumePendingRequest(self::REQUEST_ID, self::IDP_ENTITY_ID, self::ACS);
    }

    public function testUnsignedResponseWithoutDestinationIsAddressedToTheExpectedDestination()
    {
        $this->useIdentityProvider();
        $assertion = $this->signedAssertionXml($this->assertionXml(), self::RSA_SHA512);
        $this->postMessage('SAMLResponse', $this->responseXml(destination: null, assertions: $assertion));

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertSame(self::ACS, $response->getDestination());
        $this->assertNull($response->getSignatureMethod());
        $this->assertSame(self::RSA_SHA512, $response->getAssertionSignatureMethod());
        Phake::verify($this->proxyServer)->findRequestFromRequestId(self::REQUEST_ID);
        Phake::verify($this->proxyServer)->consumePendingRequest(self::REQUEST_ID, self::IDP_ENTITY_ID, self::ACS);
    }

    public function testSignedResponseWithoutDestinationIsRejected()
    {
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->signedResponseXml($this->responseXml(destination: null), 'idp'));

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);
        $this->expectExceptionMessage('Signed Response has no Destination');

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    #[DataProvider('uncorrelatedAssertionProvider')]
    public function testUnsignedResponseRequiresTheValidatedAssertionToCorrelate(
        array $assertionOptions,
        string $expectedMessage
    ): void
    {
        $this->useIdentityProvider();
        $assertion = $this->signedAssertionXml($this->assertionXml(...$assertionOptions));
        $this->postMessage('SAMLResponse', $this->responseXml(assertions: $assertion));

        try {
            $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
            $this->fail('Expected the response to be rejected');
        } catch (ResponseProcessingFailedException $exception) {
            $this->assertStringContainsString($expectedMessage, $exception->getMessage());
            Phake::verify($this->proxyServer, Phake::never())->consumePendingRequest(Phake::anyParameters());
        }
    }

    public static function uncorrelatedAssertionProvider(): array
    {
        return [
            'no InResponseTo' => [
                ['inResponseTo' => null],
                'requires a SubjectConfirmation with Recipient and InResponseTo',
            ],
            'no Recipient' => [
                ['recipient' => null],
                'requires a SubjectConfirmation with Recipient and InResponseTo',
            ],
            'other issuer' => [
                ['issuer' => 'https://other-idp.example.edu/metadata'],
                'The Assertion Issuer does not match the Response Issuer',
            ],
            'other InResponseTo' => [['inResponseTo' => '_other-request'], 'does not match the Response InResponseTo'],
            'other Recipient' => [
                ['recipient' => 'https://engine.example.org/other-acs'],
                'does not match the current destination',
            ],
        ];
    }

    #[DataProvider('mismatchedSubjectConfirmationProvider')]
    public function testBindingsRejectMismatchedConfirmationEvenAfterAssertionValidation(array $assertionOptions): void
    {
        $response = Response::fromXML($this->documentElement($this->responseXml()));
        $assertion = $this->parseAssertion($this->assertionXml(...$assertionOptions));

        $this->expectException(ResponseProcessingFailedException::class);
        $this->expectExceptionMessage('The SubjectConfirmation does not match the expected recipient and request');

        $this->invokePrivate('assertVerifiedCorrelation', $response, $assertion, self::ACS);
    }

    public static function mismatchedSubjectConfirmationProvider(): array
    {
        return [
            'other InResponseTo' => [['inResponseTo' => '_other-request']],
            'other Recipient' => [['recipient' => 'https://engine.example.org/other-acs']],
        ];
    }

    public function testExpiredAssertionIsReportedAsAClockIssue()
    {
        $this->useIdentityProvider();
        $assertion = $this->assertionXml(notBefore: '2026-11-04T10:55:00Z', notOnOrAfter: '2026-11-04T11:00:00Z');
        $this->postMessage('SAMLResponse', $this->signedResponseXml($this->responseXml(assertions: $assertion), 'idp'));

        $this->expectException(EngineBlock_Corto_Module_Bindings_ClockIssueException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    #[DataProvider('unsupportedEncryptionLayoutProvider')]
    public function testUnsupportedEncryptedAssertionLayoutsAreRejected(string $keyInfo, string $siblings)
    {
        $this->useIdentityProvider();
        $assertion = $this->encryptedAssertionXml($keyInfo, $siblings);
        $this->postMessage('SAMLResponse', $this->signedResponseXml($this->responseXml(assertions: $assertion), 'idp'));

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);
        $this->expectExceptionMessage('Unsupported EncryptedAssertion layout');

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public static function unsupportedEncryptionLayoutProvider(): array
    {
        $oaep = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

        return [
            'multiple keys in KeyInfo' => [self::encryptedKey($oaep) . self::encryptedKey($oaep), ''],
            'inline key plus sibling key' => [self::encryptedKey($oaep), self::encryptedKey($oaep)],
            'RetrievalMethod to sibling key' => [self::retrievalMethod(), self::encryptedKey($oaep)],
            'no key' => ['', ''],
        ];
    }

    public function testErrorResponseForAnotherDestinationIsRejected()
    {
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->errorResponseXml(destination: 'https://engine.example.org/other'));

        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testErrorResponseWithAnInvalidSignatureIsRejected()
    {
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->signedResponseXml($this->errorResponseXml(), 'other'));

        $this->expectException(ResponseProcessingFailedException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testErrorResponseIsCorrelatedBeforeItIsReported()
    {
        $this->useMfaHelper(false);
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->signedResponseXml($this->errorResponseXml(), 'idp'));

        try {
            $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
            $this->fail('An error response must be reported');
        } catch (EngineBlock_Corto_Exception_ReceivedErrorStatusCode $exception) {
            $this->assertSame('Responder/AuthnFailed', $exception->getFeedbackStatusCode());
            $this->assertSame('Authentication failed', $exception->getFeedbackStatusMessage());
            $this->assertSame('_request-from-sp', $exception->getFeedbackInfo()['samlRequestId']);
            $this->assertSame(self::SP_ENTITY_ID, $exception->getFeedbackInfo()['samlServiceProvider']);
        }

        Phake::verify($this->proxyServer)->findRequestFromRequestId(self::REQUEST_ID);
        Phake::verify($this->proxyServer)->consumePendingRequest(self::REQUEST_ID, self::IDP_ENTITY_ID, self::ACS);
        Phake::verify($this->mfaHelper)->isTransparent(self::SP_ENTITY_ID, self::IDP_ENTITY_ID);
    }

    public function testErrorResponseIsForwardedForTransparentMfa()
    {
        $this->useMfaHelper(true);
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->errorResponseXml(), 'state');

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertTrue($response->isTransparentErrorResponse());
        $this->assertSame('state', $response->getRelayState());
        $this->assertSame([], $response->getAssertions());
    }

    public function testUncorrelatedErrorResponseIsNotReported()
    {
        Phake::when($this->proxyServer)->findRequestFromRequestId(self::REQUEST_ID)->thenThrow(
            new EngineBlock_Corto_Module_Services_SessionLostException('Session lost')
        );
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->errorResponseXml());

        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testNoPassiveErrorResponseIsReturnedWithItsRelayState()
    {
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->errorResponseXml(subCode: Constants::STATUS_NO_PASSIVE), 'state');

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertSame('state', $response->getRelayState());
        $this->assertSame([], $response->getAssertions());
        $this->assertSame(Constants::STATUS_NO_PASSIVE, $response->getStatus()['SubCode']);
        $this->assertNull($response->getSignatureMethod());
        $this->assertNull($response->getAssertionSignatureMethod());
    }

    public function testEncryptedAssertionUsesOnlyTheDefaultLocalKeyWhenAnotherRouteKeyIsSelected()
    {
        $this->useIdentityProvider();
        $features = Phake::mock(FeatureConfiguration::class);
        Phake::when($features)->isEnabled('eb.encrypted_assertions')->thenReturn(true);
        (new ReflectionProperty(EngineBlock_Corto_Module_Bindings::class, '_featureConfiguration'))
            ->setValue($this->bindings, $features);
        Phake::when($this->proxyServer)->getKeyId()->thenReturn('rollover');
        Phake::when($this->proxyServer)->getSigningCertificates(false)
            ->thenThrow(new RuntimeException('The route key must not be used for decryption'));
        $encrypted = XmlSecurity::encryptAssertion(
            $this->documentElement($this->signedAssertionXml($this->assertionXml())),
            file_get_contents(__DIR__ . '/test.pem.crt'),
            null,
            XmlSecurityConstants::BLOCK_ENC_AES128,
            XmlSecurityConstants::KEY_TRANSPORT_OAEP_MGF1P
        );
        $this->postMessage('SAMLResponse', $this->signedResponseXml(
            $this->responseXml(assertions: $this->saveXml($encrypted)),
            'idp',
            self::RSA_SHA512
        ));

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertSame('john-doe', $response->getNameIdValue());
        $this->assertSame(self::RSA_SHA512, $response->getSignatureMethod());
        $this->assertSame(self::RSA_SHA256, $response->getAssertionSignatureMethod());
        Phake::verify($this->proxyServer)->getSigningCertificates(true);
    }

    public function testErrorResponseCannotSmuggleAnAssertionPastVerification()
    {
        $this->useIdentityProvider();
        $xml = str_replace('</samlp:Response>', $this->assertionXml() . '</samlp:Response>', $this->errorResponseXml());
        $this->postMessage('SAMLResponse', $xml);
        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testOptionalPostSignatureIsVerifiedAndAnnotated()
    {
        $this->useServiceProvider(['sp']);
        $this->postMessage('SAMLRequest', $this->signedAuthnRequestXml($this->authnRequestXml(), 'sp'));

        $this->assertTrue($this->bindings->receiveRequest()->wasSigned());
    }

    public function testOptionalPostSignatureFromAnUnconfiguredKeyIsRejected()
    {
        $this->useServiceProvider(['sp']);
        $this->postMessage('SAMLRequest', $this->signedAuthnRequestXml($this->authnRequestXml(), 'other'));
        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);

        $this->bindings->receiveRequest();
    }

    public function testOptionalSha1PostSignatureIsRejected()
    {
        $this->useServiceProvider(['sp']);
        $this->postMessage('SAMLRequest', $this->signedAuthnRequestXml($this->authnRequestXml(), 'sp', self::RSA_SHA1));
        $this->expectException(EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException::class);

        $this->bindings->receiveRequest();
    }

    public function testTamperedOptionalRedirectSignatureIsRejected()
    {
        $this->useServiceProvider(['sp']);
        $query = $this->signedRedirectQuery($this->authnRequestXml(), 'state', false);
        $this->redirectMessage(str_replace('RelayState=state', 'RelayState=changed', $query));
        $this->expectException(EngineBlock_Corto_Module_Bindings_VerificationException::class);

        $this->bindings->receiveRequest();
    }

    public function testSignedEnvelopeAlsoRequiresAssertionCorrelation()
    {
        $this->useIdentityProvider();
        $this->postMessage('SAMLResponse', $this->signedResponseXml(
            $this->responseXml(assertions: $this->assertionXml(recipient: null, inResponseTo: null)),
            'idp'
        ));
        $this->expectException(ResponseProcessingFailedException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testUnsignedEnvelopeFieldsAreNotRestoredIntoTheTrustedResponse()
    {
        $this->useIdentityProvider();
        $root = $this->documentElement($this->responseXml(assertions: $this->signedAssertionXml($this->assertionXml())));
        $root->setAttribute('Consent', 'urn:untrusted:consent');
        $root->setAttribute('IssueInstant', '2026-11-04T11:59:00Z');
        $originalId = $root->getAttribute('ID');
        $this->postMessage('SAMLResponse', $this->saveXml($root));

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertNotSame($originalId, $response->getId());
        $this->assertNull($response->getConsent());
        $this->assertSame(strtotime('2026-11-04T12:00:00Z'), $response->getIssueInstant());
    }

    public function testConfiguredForbiddenAssertionAlgorithmIsRejectedBeforeSessionEstablishment()
    {
        $this->useIdentityProvider();
        Phake::when($this->proxyServer)->getConfig('forbiddenSignatureMethods')->thenReturn([self::RSA_SHA512]);
        $this->postMessage('SAMLResponse', $this->responseXml(
            assertions: $this->signedAssertionXml($this->assertionXml(), self::RSA_SHA512)
        ));
        $this->expectException(EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException::class);

        try {
            $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
        } finally {
            Phake::verify($this->proxyServer, Phake::never())->consumePendingRequest(Phake::anyParameters());
        }
    }

    public function testConfiguredForbiddenErrorResponseAlgorithmIsRejected()
    {
        $this->useIdentityProvider();
        Phake::when($this->proxyServer)->getConfig('forbiddenSignatureMethods')->thenReturn([self::RSA_SHA512]);
        $this->postMessage('SAMLResponse', $this->signedResponseXml($this->errorResponseXml(), 'idp', self::RSA_SHA512));
        $this->expectException(EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testNoPassiveErrorCannotBypassPendingRequestValidation()
    {
        $this->useIdentityProvider();
        Phake::when($this->proxyServer)->consumePendingRequest(self::REQUEST_ID, self::IDP_ENTITY_ID, self::ACS)
            ->thenThrow(new EngineBlock_Corto_Module_Services_SessionLostException('Expired request'));
        $this->postMessage('SAMLResponse', $this->errorResponseXml(subCode: Constants::STATUS_NO_PASSIVE));
        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);

        $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
    }

    public function testAgentRouteKeySignsTheOutgoingResponseWithoutALocalPrivateKey()
    {
        $agent = $this->useAgentKeys();
        $twig = $this->createMock(Twig\Environment::class);
        $twig->expects($this->once())
            ->method('render')
            ->with('@theme/Authentication/View/Proxy/form.html.twig', $this->callback(function (array $parameters) use (&$message) {
                $message = $parameters['message'];
                return true;
            }))
            ->willReturn('rendered');

        $response = $this->createPostResponse();
        $response->setDeliverByBinding(Constants::BINDING_HTTP_POST);
        $this->createBindingsWithTwig($twig)->send(
            $response,
            new ServiceProvider('https://sp.example.edu', signatureMethod: self::RSA_SHA384, signResponse: true)
        );

        $this->assertSame(['eb-rollover', 'eb-rollover'], $agent->keysUsedFor('sign'));
        $this->assertSame([], $agent->keysUsedFor('decrypt'));
        $sentResponse = Response::fromXML(DOMDocumentFactory::fromString(base64_decode($message, true))->documentElement);
        $verifier = XmlSecurity::verifier(GeneratedKeyPair::named('eb-rollover')->certificatePem(), self::RSA_SHA384);
        $this->assertInstanceOf(Response::class, $sentResponse->verify($verifier));
        $this->assertInstanceOf(Assertion::class, $sentResponse->getAssertions()[0]->verify($verifier));
    }

    #[DataProvider('agentRedirectProvider')]
    public function testAgentSignsRedirectRequestsOnlyWhenRequired(bool $mustBeSigned, bool $useDefaultKey, array $expectedKeys)
    {
        $agent = $this->useAgentKeys();
        $request = EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(
            ['destination' => 'https://idp.example.com/sso', 'issuer' => self::EB_SP_ENTITY_ID],
            'state'
        );
        $request->setDeliverByBinding(Constants::BINDING_HTTP_REDIRECT);

        $this->bindings->send(
            $request,
            new IdentityProvider('https://idp.example.com', requestsMustBeSigned: $mustBeSigned),
            $useDefaultKey
        );

        $this->assertSame($expectedKeys, $agent->keysUsedFor('sign'));
        Phake::verify($this->proxyServer)->redirect(Phake::capture($redirectUrl), Phake::capture($redirectedMessage));
        $this->assertSame($mustBeSigned, str_contains($redirectUrl, '&Signature='));
    }

    public static function agentRedirectProvider(): array
    {
        return [
            'unsigned request makes no agent call' => [false, false, []],
            'signed request uses the route key' => [true, false, ['eb-rollover']],
            'forced default key, as after the WAYF or for Stepup' => [true, true, ['eb-default']],
        ];
    }

    public function testAgentSigningFailureSendsNothingAndKeepsOnlyARedactedDiagnostic()
    {
        $agent = $this->useAgentKeys();
        $agent->beUnreachable();
        $twig = $this->createMock(Twig\Environment::class);
        $twig->expects($this->never())->method('render');
        $response = $this->createPostResponse();
        $response->setDeliverByBinding(Constants::BINDING_HTTP_POST);

        try {
            $this->createBindingsWithTwig($twig)->send($response, new ServiceProvider('https://sp.example.edu'));
            $this->fail('Sending must fail when the agent is unreachable');
        } catch (EngineBlock_Corto_Module_Bindings_Exception $exception) {
            $this->assertStringContainsString('AgentUnavailableException: Agent is unreachable.', $exception->getMessage());
            $this->assertNull($exception->getPrevious());
        }

        $this->assertCount(1, $agent->requests, 'An agent failure is not retried');
        Phake::verify($this->proxyServer, Phake::never())->sendOutput(Phake::anyParameters());
    }

    public function testAgentDecryptsWithOnlyTheDefaultKeyWhenAnotherRouteKeyIsSelected()
    {
        $agent = $this->useAgentKeys();
        Phake::when($this->proxyServer)->getSigningCertificates(false)
            ->thenThrow(new RuntimeException('The route key must not be used for decryption'));
        $this->postMessage('SAMLResponse', $this->encryptedResponseXml('eb-default'));

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertSame('john-doe', $response->getNameIdValue());
        $this->assertSame(['eb-default'], $agent->keysUsedFor('decrypt'));
        $this->assertSame([], $agent->keysUsedFor('sign'));
    }

    public function testAgentDecryptionNeverTriesKeysOutsideTheDefaultScope()
    {
        $agent = $this->useAgentKeys();
        $this->postMessage('SAMLResponse', $this->encryptedResponseXml('eb-other'));
        $this->expectException(ResponseProcessingFailedException::class);

        try {
            $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
        } finally {
            // The registered agent could decrypt with "eb-other", but only the default key is a candidate.
            $this->assertSame(['eb-default'], $agent->keysUsedFor('decrypt'));
            Phake::verify($this->proxyServer, Phake::never())->consumePendingRequest(Phake::anyParameters());
        }
    }

    #[DataProvider('unrelatedCertificateHintProvider')]
    public function testAgentDecryptionRejectsAnyUnrelatedCertificateHintBeforeAnAgentCall(
        string $recipient,
        array $namedCertificates
    ) {
        $agent = $this->useAgentKeys();
        $this->postMessage('SAMLResponse', $this->encryptedResponseXml($recipient, namedCertificates: $namedCertificates));

        try {
            $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
            $this->fail('An EncryptedKey naming an unrelated certificate must be rejected');
        } catch (EngineBlock_Corto_Module_Bindings_VerificationException $exception) {
            $this->assertStringContainsString(
                'names a certificate other than the default decryption certificate',
                $exception->getMessage()
            );
        }

        $this->assertSame([], $agent->requests);
    }

    public static function unrelatedCertificateHintProvider(): array
    {
        return [
            'only an unrelated certificate' => ['eb-other', ['eb-other']],
            'the default and an unrelated certificate' => ['eb-default', ['eb-default', 'eb-other']],
            'an unrelated and the default certificate' => ['eb-default', ['eb-other', 'eb-default']],
        ];
    }

    public function testAgentDecryptsWhenTheEncryptedKeyNamesOnlyTheDefaultCertificate()
    {
        $agent = $this->useAgentKeys();
        $this->postMessage('SAMLResponse', $this->encryptedResponseXml('eb-default', namedCertificates: ['eb-default']));

        $response = $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);

        $this->assertSame('john-doe', $response->getNameIdValue());
        $this->assertSame(['eb-default'], $agent->keysUsedFor('decrypt'));
    }

    public function testParameterlessRsaOaepIsRejectedBeforeAnAgentCall()
    {
        $agent = $this->useAgentKeys();
        $this->postMessage(
            'SAMLResponse',
            $this->encryptedResponseXml('eb-default', XmlSecurityConstants::KEY_TRANSPORT_OAEP)
        );

        try {
            $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
            $this->fail('Parameterless xmlenc11#rsa-oaep must be rejected in agent mode');
        } catch (EngineBlock_Corto_Module_Bindings_VerificationException $exception) {
            $this->assertStringContainsString('requires explicit DigestMethod and MGF', $exception->getMessage());
        }

        $this->assertSame([], $agent->requests);
    }

    public function testParameterlessRsaOaepStillDecryptsWithALocalDefaultKey()
    {
        $this->useIdentityProvider();
        $this->enableEncryptedAssertions();
        $encrypted = XmlSecurity::encryptAssertion(
            $this->documentElement($this->signedAssertionXml($this->assertionXml())),
            file_get_contents(__DIR__ . '/test.pem.crt'),
            null,
            XmlSecurityConstants::BLOCK_ENC_AES128,
            XmlSecurityConstants::KEY_TRANSPORT_OAEP
        );
        $this->postMessage('SAMLResponse', $this->signedResponseXml(
            $this->responseXml(assertions: $this->saveXml($encrypted)),
            'idp'
        ));

        $this->assertSame('john-doe', $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS)->getNameIdValue());
    }

    public function testAgentDecryptionOutageFailsWithoutFallbackOrSession()
    {
        $agent = $this->useAgentKeys();
        $agent->failWithStatus(503);
        $this->postMessage('SAMLResponse', $this->encryptedResponseXml('eb-default'));

        try {
            $this->bindings->receiveResponse(self::EB_SP_ENTITY_ID, self::ACS);
            $this->fail('Decryption must fail when the agent is unavailable');
        } catch (ResponseProcessingFailedException $exception) {
            $this->assertStringContainsString(
                'AgentUnavailableException: Agent temporarily unavailable (HTTP 503).',
                $exception->getMessage()
            );
            $this->assertNull($exception->getPrevious());
        }

        $this->assertCount(1, $agent->requests, 'An agent failure is not retried');
        Phake::verify($this->proxyServer, Phake::never())->consumePendingRequest(Phake::anyParameters());
    }

    /**
     * The default key decrypts and signs through agent key "eb-default", route key "rollover" signs through
     * "eb-rollover". The agent also holds "eb-other" with "decrypt", so the bundle-wide key name resolver is
     * broader than EngineBlock's default-only decryption scope. No local private key is configured.
     */
    private function useAgentKeys(): FakePrivateKeyAgent
    {
        $encryptionKeys = [
            'default' => self::agentKeyConfiguration('eb-default', ['sign', 'decrypt']),
            'rollover' => self::agentKeyConfiguration('eb-rollover', ['sign']),
        ];
        $agentKeys = SamlBundleConfiguration::build(EncryptionKeysConfiguration::fromArray($encryptionKeys), [])
            ['private_key_agent']['keys'];
        $agentKeys['eb-other'] = [
            'certificate_file' => GeneratedKeyPair::named('eb-other')->certificateFile(),
            'token' => 'other-token',
            'operations' => ['decrypt'],
        ];

        $agent = new FakePrivateKeyAgent(array_map(
            static fn (string $name): string => GeneratedKeyPair::named($name)->privateKeyPem(),
            ['eb-default' => 'eb-default', 'eb-rollover' => 'eb-rollover', 'eb-other' => 'eb-other']
        ));
        $agent->register($agentKeys);

        Phake::when($this->proxyServer)->getSigningCertificates(true)
            ->thenReturn(EngineBlock_X509_KeyPair::forPrivateKeyAgent(self::certificate('eb-default')));
        Phake::when($this->proxyServer)->getSigningCertificates(false)
            ->thenReturn(EngineBlock_X509_KeyPair::forPrivateKeyAgent(self::certificate('eb-rollover')));

        // The decrypter chain of config/services/saml_bundle.yml, for these keys.
        $logger = new NullLogger();
        $decrypter = new PolicyCheckingAssertionDecrypter(new AgentAssertionDecrypter(
            new LocalAssertionDecrypter(new PrivateKeyLoader()),
            static fn () => DefaultKeyDecryptionKeyMap::create($encryptionKeys),
            $logger
        ));
        $processor = new VerifiedResponseProcessor(
            new ResponseProcessor(new KeyLoader(), new PrivateKeyLoader(), $logger, null, $decrypter),
            new ResponseEnvelopeVerifier($logger),
            $decrypter
        );
        $symfonyContainer = (new ReflectionProperty(EngineBlock_Application_DiContainer::class, 'container'))
            ->getValue($this->originalDiContainer);
        $diContainer = Phake::partialMock(get_class($this->originalDiContainer), $symfonyContainer);
        Phake::when($diContainer)->getSamlVerifiedResponseProcessor()->thenReturn($processor);
        $this->setDiContainer($diContainer);

        $this->useIdentityProvider();
        $this->enableEncryptedAssertions();

        return $agent;
    }

    private static function agentKeyConfiguration(string $name, array $operations): array
    {
        return [
            'backend' => 'agent',
            'publicFile' => GeneratedKeyPair::named($name)->certificateFile(),
            'agent' => ['key' => $name, 'token' => $name . '-token', 'operations' => $operations],
        ];
    }

    private function enableEncryptedAssertions(): void
    {
        $features = Phake::mock(FeatureConfiguration::class);
        Phake::when($features)->isEnabled('eb.encrypted_assertions')->thenReturn(true);
        (new ReflectionProperty(EngineBlock_Corto_Module_Bindings::class, '_featureConfiguration'))
            ->setValue($this->bindings, $features);
    }

    /**
     * A signed Response with a signed assertion encrypted to the certificate of $recipient, optionally naming
     * certificates in the KeyInfo of the EncryptedKey.
     *
     * @param list<string> $namedCertificates
     */
    private function encryptedResponseXml(
        string $recipient,
        string $keyTransportAlgorithm = XmlSecurityConstants::KEY_TRANSPORT_OAEP_MGF1P,
        array $namedCertificates = []
    ): string {
        $encrypted = XmlSecurity::encryptAssertion(
            $this->documentElement($this->signedAssertionXml($this->assertionXml())),
            GeneratedKeyPair::named($recipient)->certificatePem(),
            null,
            XmlSecurityConstants::BLOCK_ENC_AES128,
            $keyTransportAlgorithm
        );

        if ($namedCertificates !== []) {
            $encryptionMethod = $encrypted->getElementsByTagNameNS(Constants::NS_XENC, 'EncryptedKey')->item(0)
                ->getElementsByTagNameNS(Constants::NS_XENC, 'EncryptionMethod')->item(0);
            $keyInfo = $this->documentElement(sprintf(
                '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%s</ds:KeyInfo>',
                implode('', array_map(
                    static fn (string $name): string => sprintf(
                        '<ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>',
                        GeneratedKeyPair::named($name)->certificateData()
                    ),
                    $namedCertificates
                ))
            ));
            $encryptionMethod->after($encrypted->ownerDocument->importNode($keyInfo, true));
        }

        return $this->signedResponseXml($this->responseXml(assertions: $this->saveXml($encrypted)), 'idp');
    }

    private static function encryptedKey(string $algorithm): string
    {
        return sprintf(
            '<xenc:EncryptedKey Id="key"><xenc:EncryptionMethod Algorithm="%s"/>'
            . '<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>',
            $algorithm
        );
    }

    private static function retrievalMethod(): string
    {
        return '<ds:RetrievalMethod URI="#key" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey"/>';
    }

    private function encryptedAssertionXml(string $keyInfo, string $siblings): string
    {
        $keyInfo = $keyInfo === '' ? '' : "<ds:KeyInfo>$keyInfo</ds:KeyInfo>";

        return <<<XML
<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
    $keyInfo
    <xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData>
  </xenc:EncryptedData>
  $siblings
</saml:EncryptedAssertion>
XML;
    }

    private function assertionXml(
        string $issuer = self::IDP_ENTITY_ID,
        ?string $recipient = self::ACS,
        ?string $inResponseTo = self::REQUEST_ID,
        string $notBefore = '2026-11-04T11:55:00Z',
        string $notOnOrAfter = '2026-11-04T12:05:00Z'
    ): string {
        $confirmationData = sprintf('NotOnOrAfter="%s"', $notOnOrAfter)
            . ($recipient === null ? '' : sprintf(' Recipient="%s"', $recipient))
            . ($inResponseTo === null ? '' : sprintf(' InResponseTo="%s"', $inResponseTo));

        return sprintf(
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z"><saml:Issuer>%s</saml:Issuer>'
            . '<saml:Subject><saml:NameID>john-doe</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData %s/></saml:SubjectConfirmation></saml:Subject>'
            . '<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">'
            . '<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            . '<saml:AuthnStatement AuthnInstant="2026-11-04T12:00:00Z"><saml:AuthnContext>'
            . '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
            . '</saml:AuthnContext></saml:AuthnStatement></saml:Assertion>',
            bin2hex(random_bytes(16)),
            $issuer,
            $confirmationData,
            $notBefore,
            $notOnOrAfter,
            self::EB_SP_ENTITY_ID
        );
    }

    private function responseXml(?string $destination = self::ACS, ?string $assertions = null, ?string $status = null): string
    {
        return sprintf(
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z"%s InResponseTo="%s">'
            . '<saml:Issuer>%s</saml:Issuer><samlp:Status>%s</samlp:Status>%s</samlp:Response>',
            bin2hex(random_bytes(16)),
            $destination === null ? '' : sprintf(' Destination="%s"', $destination),
            self::REQUEST_ID,
            self::IDP_ENTITY_ID,
            $status ?? '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>',
            $assertions ?? $this->assertionXml()
        );
    }

    private function errorResponseXml(
        string $destination = self::ACS,
        string $subCode = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'
    ): string {
        return $this->responseXml(
            destination: $destination,
            assertions: '',
            status: sprintf(
                '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">'
                . '<samlp:StatusCode Value="%s"/></samlp:StatusCode>'
                . '<samlp:StatusMessage>Authentication failed</samlp:StatusMessage>',
                $subCode
            )
        );
    }

    private function authnRequestXml(?string $destination = '', bool $nameIdPolicy = false): string
    {
        if ($destination === '') {
            $destination = $this->singleSignOnLocation();
        }

        return sprintf(
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z"%s'
            . ' AssertionConsumerServiceURL="https://sp.example.edu/acs">'
            . '<saml:Issuer>%s</saml:Issuer>%s</samlp:AuthnRequest>',
            bin2hex(random_bytes(16)),
            $destination === null ? '' : sprintf(' Destination="%s"', $destination),
            self::SP_ENTITY_ID,
            $nameIdPolicy ? sprintf('<samlp:NameIDPolicy Format="%s" AllowCreate="true"/>', self::NAMEID_TRANSIENT) : ''
        );
    }

    private function signedAuthnRequestXml(string $xml, string $signer, string $algorithm = self::RSA_SHA256): string
    {
        // saml2 v7 rejects AllowCreate on a transient NameIDPolicy, so sign the request without it.
        $xml = str_replace(' AllowCreate="true"', '', $xml);
        $request = AuthnRequest::fromXML($this->documentElement($xml));
        $request->sign(
            (new SignatureAlgorithmFactory([]))->getAlgorithm($algorithm, GeneratedKeyPair::named($signer)->privateKey())
        );

        return $this->saveXml($request->toXML());
    }

    private function signedAssertionXml(string $xml, string $algorithm = self::RSA_SHA256): string
    {
        $assertion = $this->parseAssertion($xml);
        $assertion->sign(
            (new SignatureAlgorithmFactory([]))->getAlgorithm($algorithm, GeneratedKeyPair::named('idp')->privateKey())
        );

        return $this->saveXml($assertion->toXML());
    }

    private function signedResponseXml(string $xml, string $signer, string $algorithm = self::RSA_SHA256): string
    {
        $response = Response::fromXML($this->documentElement($xml));
        $response->sign(
            (new SignatureAlgorithmFactory([]))->getAlgorithm($algorithm, GeneratedKeyPair::named($signer)->privateKey())
        );

        return $this->saveXml($response->toXML());
    }

    private function signedRedirectQuery(string $xml, ?string $relayState, bool $lowercasePercentEncoding): string
    {
        $query = 'SAMLRequest=' . urlencode(base64_encode(gzdeflate($xml)));
        if ($relayState !== null) {
            $query .= '&RelayState=' . urlencode($relayState);
        }
        $query .= '&SigAlg=' . urlencode(self::RSA_SHA256);
        if ($lowercasePercentEncoding) {
            $query = self::lowercasePercentEncoding($query);
        }

        openssl_sign($query, $signature, GeneratedKeyPair::named('sp')->privateKeyPem(), OPENSSL_ALGO_SHA256);

        return $query . '&Signature=' . urlencode(base64_encode($signature));
    }

    private static function lowercasePercentEncoding(string $query): string
    {
        return preg_replace_callback('/%[0-9A-F]{2}/', static fn(array $match) => strtolower($match[0]), $query);
    }

    private function parseAssertion(string $xml): Assertion
    {
        return Assertion::fromXML($this->documentElement($xml));
    }

    private function documentElement(string $xml): Dom\Element
    {
        return DOMDocumentFactory::fromString($xml)->documentElement;
    }

    private function saveXml(Dom\Element $element): string
    {
        return $element->ownerDocument->saveXml($element);
    }

    private function singleSignOnLocation(): string
    {
        return EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()->getUrlProvider()
            ->getUrl('authentication_idp_sso', true, null, null);
    }

    private function useServiceProvider(array $certificates = [], bool $requestsMustBeSigned = false): void
    {
        $serviceProvider = new ServiceProvider(
            self::SP_ENTITY_ID,
            certificates: array_map(self::metadataCertificate(...), $certificates),
            requestsMustBeSigned: $requestsMustBeSigned
        );
        Phake::when($this->proxyServer)->getRepository()->thenReturn(new InMemoryMetadataRepository([], [$serviceProvider]));
    }

    private function useMfaHelper(bool $isTransparent): void
    {
        $originalRequest = Phake::mock(EngineBlock_Saml2_AuthnRequestAnnotationDecorator::class);
        Phake::when($originalRequest)->getId()->thenReturn('_request-from-sp');
        Phake::when($originalRequest)->getIssuerValue()->thenReturn(self::SP_ENTITY_ID);
        Phake::when($this->proxyServer)->findRequestFromRequestId(self::REQUEST_ID)->thenReturn($originalRequest);

        $this->mfaHelper = Phake::mock(MfaHelperInterface::class);
        Phake::when($this->mfaHelper)->isTransparent(Phake::anyParameters())->thenReturn($isTransparent);

        $symfonyContainer = (new ReflectionProperty(EngineBlock_Application_DiContainer::class, 'container'))
            ->getValue($this->originalDiContainer);
        $diContainer = Phake::partialMock(get_class($this->originalDiContainer), $symfonyContainer);
        Phake::when($diContainer)->getMfaHelper()->thenReturn($this->mfaHelper);
        $this->setDiContainer($diContainer);
    }

    private function setDiContainer($diContainer): void
    {
        $property = new ReflectionProperty(EngineBlock_ApplicationSingleton::class, '_diContainer');
        $property->setValue(EngineBlock_ApplicationSingleton::getInstance(), $diContainer);
    }

    private function useIdentityProvider(): void
    {
        $identityProvider = new IdentityProvider(self::IDP_ENTITY_ID, certificates: [self::metadataCertificate('idp')]);
        Phake::when($this->proxyServer)->getRepository()->thenReturn(new InMemoryMetadataRepository([$identityProvider], []));
    }

    private static function metadataCertificate(string $name): X509CertificateLazyProxy
    {
        return new X509CertificateLazyProxy(
            new X509CertificateFactory(),
            GeneratedKeyPair::named($name)->certificateData()
        );
    }

    private static function certificate(string $name): EngineBlock_X509_Certificate
    {
        $pem = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(GeneratedKeyPair::named($name)->certificateData(), 64, "\n")
            . "-----END CERTIFICATE-----\n";

        return new EngineBlock_X509_Certificate(openssl_x509_read($pem));
    }

    private function postMessage(string $parameter, string $xml, ?string $relayState = null): void
    {
        $post = [$parameter => base64_encode($xml)];
        if ($relayState !== null) {
            $post['RelayState'] = $relayState;
        }

        $request = new EngineBlock_Http_Request();
        $request->setMethod('POST');
        (new ReflectionMethod(EngineBlock_Http_Request::class, '_setPostParameters'))->invoke($request, $post);
        EngineBlock_ApplicationSingleton::getInstance()->setHttpRequest($request);
    }

    private function redirectMessage(string $queryString): void
    {
        $request = new EngineBlock_Http_Request();
        $request->setMethod('GET');
        $request->setQueryString($queryString);
        (new ReflectionMethod(EngineBlock_Http_Request::class, '_setPostParameters'))->invoke($request, []);
        EngineBlock_ApplicationSingleton::getInstance()->setHttpRequest($request);
    }

    private function invokePrivate(string $methodName, ...$arguments): void
    {
        $method = new ReflectionMethod(EngineBlock_Corto_Module_Bindings::class, $methodName);
        $method->invoke($this->bindings, ...$arguments);
    }

    private function mockLogger()
    {
        $logger = m::mock();

        $loggerProperty = new ReflectionProperty(EngineBlock_Corto_Module_Bindings::class, '_logger');
        $loggerProperty->setValue($this->bindings, $logger);

        return $logger;
    }

    private function checkIssueInstant($issueInstant, $type, $entityId)
    {
        $method = new ReflectionMethod(EngineBlock_Corto_Module_Bindings::class, '_checkIssueInstant');
        $method->invoke($this->bindings, $issueInstant, $type, $entityId);
    }
}
