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

use OpenConext\EngineBlock\Metadata\Entity\AbstractRole;
use OpenConext\EngineBlock\Metadata\Entity\IdentityProvider;
use OpenConext\EngineBlock\Metadata\Entity\ServiceProvider;
use OpenConext\EngineBlock\Validator\AllowedSchemeValidator;
use OpenConext\EngineBlockBundle\Exception\ResponseProcessingFailedException;
use Dom\Element;
use Dom\XPath;
use OpenConext\EngineBlock\Saml2\Bundle\Exception\UnsupportedSignatureAlgorithmException;
use OpenConext\EngineBlock\Saml2\Bundle\PrivateKeyAgentFailure;
use OpenConext\EngineBlock\Saml2\Bundle\ResponseEnvelopeVerifier;
use OpenConext\EngineBlock\Saml2\Bundle\SignatureAlgorithmPolicy;
use OpenConext\EngineBlock\Saml2\Bundle\SignerFactory;
use OpenConext\EngineBlock\Saml2\Bundle\UnsignedRedirectEncoder;
use OpenConext\EngineBlock\Saml2\Message\MessageRebuilder;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use SimpleSAML\SAML2\Configuration\PrivateKey as Saml2PrivateKey;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\saml\Assertion as V7Assertion;
use SimpleSAML\SAML2\XML\samlp\AbstractMessage as V7Message;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as V7AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Response as V7Response;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as XmlSecurityConstants;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Exception\PrivateKeyAgentExceptionInterface;
use SimpleSAML\XMLSecurity\Key\PrivateKey as XmlSecurityPrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate as XmlSecurityCertificate;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate as X509CertificateElement;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use SimpleSAML\XMLSchema\Type\Base64BinaryValue;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSchema\Type\NCNameValue;
use Surfnet\SamlBundle\Entity\IdentityProvider as BundleIdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider as BundleServiceProvider;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;
use Surfnet\SamlBundle\SAML2\AuthnRequest as BundleAuthnRequest;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;
use Twig\Environment;

/**
 * The bindings module for Corto, which implements support for various data
 * bindings.
 */
class EngineBlock_Corto_Module_Bindings extends EngineBlock_Corto_Module_Abstract
{
    const KEY_REQUEST  = 'SAMLRequest';
    const KEY_RESPONSE = 'SAMLResponse';

    const SAML_STATUS_MESSAGE_EMPTY = '(No message provided)';

    const OLD_ISSUE_INSTANT_THRESHOLD_SECONDS = 86400; // 24 hours

    protected static $ASSERTION_SEQUENCE = array(
        'saml:Issuer',
        'ds:Signature',
        'saml:Subject',
        'saml:Conditions',
        'saml:Advice',
        'saml:Statement',
        'saml:AuthnStatement',
        'saml:AuhzDecisionStatement',
        'saml:AttributeStatement',
    );

    /**
     * Supported bindings in Corto.
     * @var array
     */
    protected $_bindings = array(
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'        => '_sendHTTPRedirect',
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'            => '_sendHTTPPost',
        'INTERNAL'                                                  => 'sendInternal',
        'JSON-Redirect'                                             => '_sendHTTPRedirect',
        'JSON-POST'                                                 => '_sendHTTPPost',
        ''                                                          => '_sendHTTPRedirect'
    );

    /**
     * @var array
     */
    protected $_internalBindingMessages = array();

    /**
     * @var EngineBlock_Corto_ProxyServer
     */
    #[Override]
    protected $_server;

    /**
     * @var OpenConext\EngineBlockBundle\Configuration\FeatureConfiguration
     */
    private $_featureConfiguration;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $_logger;

    /**
     * @var Environment
     */
    private $twig;

    /**
     * @var AllowedSchemeValidator
     */
    private $acsLocationSchemeValidator;

    /**
     * @var IdentityProvider
     */
    private $stepupIdentityProvider;

    public function __construct(EngineBlock_Corto_ProxyServer $server)
    {
        parent::__construct($server);

        $diContainer                       = EngineBlock_ApplicationSingleton::getInstance()->getDiContainer();
        $this->_featureConfiguration = $diContainer->getFeatureConfiguration();
        $this->_logger = EngineBlock_ApplicationSingleton::getLog();
        $this->twig = EngineBlock_ApplicationSingleton::getInstance()->getDiContainerRuntime()->twig;
        $this->acsLocationSchemeValidator = $diContainer->getAcsLocationSchemeValidator();
        $this->stepupIdentityProvider = $diContainer->getStepupIdentityProvider($this->_server);
    }

    /**
     * Process an authorization request.
     *
     * NOTE: Never call this method more than once for the same request. This method
     *       does not cache its results.
     *
     * @param string|null $idpHash The IdP hash of the dispatched single sign-on route, if any
     * @return EngineBlock_Saml2_AuthnRequestAnnotationDecorator
     * @throws EngineBlock_Corto_Module_Bindings_UnsupportedBindingException
     * @throws EngineBlock_Corto_Module_Bindings_UnableToReceiveMessageException
     * @throws EngineBlock_Corto_Module_Bindings_VerificationException
     * @throws EngineBlock_Corto_Module_Bindings_Exception
     */
    public function receiveRequest(?string $idpHash = null)
    {
        $httpRequest = EngineBlock_ApplicationSingleton::getInstance()->getHttpRequest();
        $method = strtoupper((string) $httpRequest->getMethod());
        $redirectQuery = null;

        try {
            if ($method === 'GET') {
                // Keep the original query bytes: the Redirect signature covers them as received.
                $redirectQuery = ReceivedAuthnRequestQueryString::parse((string) $httpRequest->getQueryString());
                $xml = $redirectQuery->getDecodedSamlRequest();
                $relayState = $redirectQuery->hasRelayState() ? urldecode($redirectQuery->getRelayState()) : null;
            } elseif ($method === 'POST') {
                $xml = $this->decodePostedMessage($httpRequest, self::KEY_REQUEST);
                $relayState = $this->postedRelayState($httpRequest);
            } else {
                throw new EngineBlock_Corto_Module_Bindings_UnsupportedBindingException(
                    'Unsupported Binding used',
                    EngineBlock_Exception::CODE_NOTICE
                );
            }

            $root = Saml2Value::documentElement($xml);
        } catch (EngineBlock_Corto_Module_Bindings_Exception $exception) {
            throw $exception;
        } catch (Exception $exception) {
            throw $this->unableToReceiveRequest($exception);
        }

        if (!self::isElement($root, Constants::NS_SAMLP, 'AuthnRequest')) {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedBindingException(
                'Unsupported Binding used',
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        $isSigned = $redirectQuery !== null ? $redirectQuery->isSigned() : $this->query($root, './ds:Signature') !== [];
        try {
            if ($redirectQuery !== null) {
                $receivedRequest = ReceivedAuthnRequest::fromHttpRedirectBinding($xml);
            } elseif ($this->query($root, '//ds:Signature') === []) {
                $receivedRequest = ReceivedAuthnRequest::from($this->normalizeTransientAllowCreate($root, $xml));
            } else {
                $receivedRequest = ReceivedAuthnRequest::from($xml);
            }
            $sspRequest = $this->authnRequestElement($receivedRequest);
        } catch (Exception $exception) {
            throw $this->unableToReceiveRequest($exception);
        }

        $issuer = $receivedRequest->getServiceProvider();
        $signatureMethod = $redirectQuery !== null
            ? ($isSigned ? $redirectQuery->getSignatureAlgorithm() : null)
            : $this->getXmlSignatureMethod($root);

        if ($signatureMethod !== null) {
            $log = $this->_server->getLogger();

            $log->notice(sprintf(
                'Received signed AuthnRequest from Issuer "%s" with signature method algorithm "%s"',
                $issuer,
                $signatureMethod
            ));

            $forbiddenSignatureMethods = $this->_server->getConfig('forbiddenSignatureMethods');
            if (in_array($signatureMethod, $forbiddenSignatureMethods)) {
                throw new EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException($signatureMethod);
            }
        }

        // Make sure the request from the sp has an Issuer
        if ($issuer === null) {
            throw new EngineBlock_Corto_Module_Bindings_Exception(
                'Missing <saml:Issuer> in message delivered to AssertionConsumerService.'
            );
        }

        // Verify that we know this SP and have metadata for it.
        $serviceProvider = $this->_verifyKnownSP($issuer);

        if (!$serviceProvider instanceof ServiceProvider) {
            throw new EngineBlock_Corto_Module_Bindings_Exception(
                sprintf("Requesting entity '%s' is not a Service Provider", $issuer)
            );
        }

        $requestsMustBeSigned = $serviceProvider->requestsMustBeSigned;
        $isTrustedProxy = $serviceProvider->getCoins()->isTrustedProxy();

        if ($isTrustedProxy && !$requestsMustBeSigned){
            throw new EngineBlock_Corto_Module_Bindings_Exception(
                sprintf(
                    'SP "%s" is marked as Trusted Proxy but does not have "redirect:sign" enabled.',
                    $issuer
                )
            );
        }

        // Determine if we should check the signature of the message
        $wantRequestsSigned = (
            // If the destination wants the AuthnRequests signed
            $requestsMustBeSigned
            ||
            // Or we currently demand that all AuthnRequests are sent signed
            $this->_server->getConfig('WantsAuthnRequestsSigned')
        );

        // If we should, then check it and continue with the request as covered by the signature.
        if ($wantRequestsSigned || $isSigned) {
            $receivedRequest = $redirectQuery !== null
                ? $this->verifyRedirectSignature($serviceProvider, $redirectQuery, $receivedRequest)
                : $this->verifyPostSignature($serviceProvider, $receivedRequest, $signatureMethod);
            $sspRequest = $this->authnRequestElement($receivedRequest);
        }

        if ($receivedRequest->getServiceProvider() !== $serviceProvider->entityId) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'The verified AuthnRequest Issuer does not match the service provider'
            );
        }

        // Apply policy to the content returned by verification, rather than its unverified wrapper.
        $this->assertValidAcsLocationScheme($sspRequest->getAssertionConsumerServiceURL()?->getValue());
        $this->_checkIssueInstant(Saml2Value::timestamp($sspRequest->getIssueInstant()), 'SP', $issuer);
        $this->assertRequestDestination($receivedRequest->getDestination(), $isSigned, $idpHash);

        EngineBlock_ApplicationSingleton::getInstance()->getDiContainerRuntime()->feedbackStateHelper->startNewFlow(
            $receivedRequest->getRequestId(),
            $issuer
        );

        $ebRequest = new EngineBlock_Saml2_AuthnRequestAnnotationDecorator($sspRequest, $relayState);
        if ($isSigned) {
            $ebRequest->setWasSigned();
        }

        $this->_annotateRequestWithKeyId($ebRequest);

        // Corto service modules (SingleSignOn) can use the received
        // request object without having to process it again.
        $this->_server->setReceivedRequest($ebRequest);

        return $ebRequest;
    }

    private function unableToReceiveRequest(Exception $exception): EngineBlock_Corto_Module_Bindings_UnableToReceiveMessageException
    {
        return new EngineBlock_Corto_Module_Bindings_UnableToReceiveMessageException(
            sprintf('Unable to receive the AuthnRequest: %s', $exception->getMessage()),
            EngineBlock_Exception::CODE_NOTICE,
            $exception
        );
    }

    private function authnRequestElement(ReceivedAuthnRequest $receivedRequest): V7AuthnRequest
    {
        return V7AuthnRequest::fromXML(Saml2Value::documentElement($receivedRequest->getUnsignedXML()));
    }

    /**
     * Drops AllowCreate from a direct transient NameIDPolicy child of an unsigned POST request,
     * as the bundle does for HTTP-Redirect requests. Signed requests are never rewritten.
     */
    private function normalizeTransientAllowCreate(Element $root, string $xml): string
    {
        $normalized = false;
        foreach ($this->query($root, './samlp:NameIDPolicy') as $nameIdPolicy) {
            if ($nameIdPolicy->getAttribute('Format') === Constants::NAMEID_TRANSIENT
                && in_array($nameIdPolicy->getAttribute('AllowCreate'), ['true', '1'], true)
            ) {
                $nameIdPolicy->removeAttribute('AllowCreate');
                $normalized = true;
            }
        }

        return $normalized ? Saml2Value::toXmlString($root) : $xml;
    }

    /**
     * The algorithm of the enveloped message signature, as found in the received XML.
     */
    private function getXmlSignatureMethod(Element $root): ?string
    {
        $algorithm = $this->query($root, './ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm');

        return $algorithm === [] ? null : $algorithm[0]->value;
    }

    /**
     * Verifies the original Redirect query bytes with the SP's configured certificates.
     */
    private function verifyRedirectSignature(
        ServiceProvider $serviceProvider,
        ReceivedAuthnRequestQueryString $redirectQuery,
        ReceivedAuthnRequest $receivedRequest
    ): ReceivedAuthnRequest {
        $certificates = $this->serviceProviderCertificates($serviceProvider);
        if (!$redirectQuery->isSigned()) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'Validation of received messages enabled, but no signature found on message.'
            );
        }

        try {
            $isSigned = EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()
                ->getSamlRedirectSignatureVerifier()
                ->isSignedBy($redirectQuery, $certificates);
        } catch (UnsupportedSignatureAlgorithmException $exception) {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException($exception->getAlgorithm());
        }

        if (!$isSigned) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'Validation of received messages enabled, but the signature could not be verified with any '
                . 'configured certificate of the service provider.'
            );
        }

        // The signature covers the encoded SAMLRequest the request was parsed from.
        return $receivedRequest;
    }

    private function verifyPostSignature(
        ServiceProvider $serviceProvider,
        ReceivedAuthnRequest $receivedRequest,
        ?string $signatureMethod
    ): ReceivedAuthnRequest {
        $certificates = $this->serviceProviderCertificates($serviceProvider);
        if ($signatureMethod === null) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'Validation of received messages enabled, but no signature found on message.'
            );
        }

        if (!in_array($signatureMethod, RSA::getSupportedAlgorithms(), true)
            || SignatureAlgorithmPolicy::isBlacklisted($signatureMethod)
        ) {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException($signatureMethod);
        }

        $lastException = null;
        foreach ($certificates as $index => $certificate) {
            try {
                $verifiedRequest = $receivedRequest->verifiedWith($certificate->getPublicKey());
            } catch (Exception $exception) {
                $this->_logger->debug(sprintf(
                    'AuthnRequest signature verification with certificate #%s failed: %s',
                    $index,
                    $exception->getMessage()
                ));
                $lastException = $exception;
                continue;
            }

            if ($verifiedRequest === null) {
                throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                    'Validation of received messages enabled, but no signature found on message.'
                );
            }

            return $verifiedRequest;
        }

        throw new EngineBlock_Corto_Module_Bindings_VerificationException(
            'Validation of received messages enabled, but the signature could not be verified with any '
            . 'configured certificate of the service provider.',
            EngineBlock_Exception::CODE_NOTICE,
            $lastException
        );
    }

    /**
     * @return XmlSecurityCertificate[]
     */
    private function serviceProviderCertificates(ServiceProvider $serviceProvider): array
    {
        /** @var EngineBlock_X509_Certificate[] $certificates */
        $certificates = $serviceProvider->certificates;
        if (empty($certificates)) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'Validation of received messages enabled, but no keys are configured for service provider.'
            );
        }

        return array_values(array_map(
            static fn(EngineBlock_X509_Certificate $certificate) => new XmlSecurityCertificate(
                PEM::fromString($certificate->toPem())
            ),
            $certificates
        ));
    }

    /**
     * Signed requests must have a Destination, and a present Destination must exactly match the
     * configured base single sign-on URL or the configured URL of the dispatched key/IdP route.
     */
    private function assertRequestDestination(?string $destination, bool $isSigned, ?string $idpHash): void
    {
        if ($destination === null) {
            if ($isSigned) {
                throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                    'Signed AuthnRequest has no Destination',
                    EngineBlock_Exception::CODE_NOTICE
                );
            }

            return;
        }

        $urlProvider = EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()->getUrlProvider();
        $baseUrl = $urlProvider->getUrl('authentication_idp_sso', true, null, null);
        $routeUrl = $baseUrl;

        $keyId = $this->_server->getKeyId();
        if ($keyId) {
            $routeUrl .= '/key:' . $keyId;
        }
        if ($idpHash !== null && $idpHash !== '') {
            $routeUrl .= '/' . $idpHash;
        }

        if ($destination !== $baseUrl && $destination !== $routeUrl) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                sprintf('AuthnRequest Destination "%s" does not match the single sign-on location', $destination),
                EngineBlock_Exception::CODE_NOTICE
            );
        }
    }

    /**
     * @param $ebRequest
     */
    protected function _annotateRequestWithKeyId(EngineBlock_Saml2_AuthnRequestAnnotationDecorator $ebRequest)
    {
        $keyId = $this->_server->getKeyId();

        if (!$keyId) {
            return;
        }

        $ebRequest->setKeyId($keyId);
    }

    /**
     * @param string $serviceEntityId
     * @param string $expectedDestination
     * @return EngineBlock_Saml2_ResponseAnnotationDecorator
     *
     * @throws EngineBlock_Corto_Exception_ReceivedErrorStatusCode
     * @throws EngineBlock_Exception_UnknownIdentityProvider
     * @throws EngineBlock_Corto_Module_Bindings_ClockIssueException
     * @throws EngineBlock_Corto_Module_Bindings_Exception
     * @throws EngineBlock_Corto_Module_Bindings_VerificationException
     * @throws EngineBlock_Corto_Module_Services_SessionLostException
     * @throws ResponseProcessingFailedException
     */
    public function receiveResponse($serviceEntityId, $expectedDestination)
    {
        // First check if we parked a Response somewhere in memory and are just faking a SSO
        if ($sspResponse = $this->_receiveMessageFromInternalBinding(self::KEY_RESPONSE)) {
            // If so, no need to do any further verification, we trust our own responses.
            return $sspResponse;
        }

        $httpRequest = EngineBlock_ApplicationSingleton::getInstance()->getHttpRequest();
        if (strtoupper((string) $httpRequest->getMethod()) !== 'POST') {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedBindingException(
                'Unsupported Binding used',
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        try {
            $xml = $this->decodePostedMessage($httpRequest, self::KEY_RESPONSE);
            $root = Saml2Value::documentElement($xml);
        } catch (Exception $exception) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                sprintf('Unable to receive the Response: %s', $exception->getMessage()),
                EngineBlock_Exception::CODE_NOTICE,
                $exception
            );
        }
        $relayState = $this->postedRelayState($httpRequest);

        if (!self::isElement($root, Constants::NS_SAMLP, 'Response')) {
            throw new EngineBlock_Corto_Module_Bindings_Exception(
                sprintf('Unsupported Message received: "%s"', $root->localName),
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        // Log the response we received for troubleshooting
        $log = $this->_server->getLogger();
        $log->info('Received response', array('saml_response' => $xml));

        // Make sure the response from the idp has an Issuer
        $issuerElement = $this->query($root, './saml:Issuer');
        if ($issuerElement === []) {
            throw new EngineBlock_Corto_Module_Bindings_Exception(
                'Missing <saml:Issuer> in message delivered to AssertionConsumerService.'
            );
        }
        $idpEntityId = trim($issuerElement[0]->textContent);

        // Remember idp for debugging
        EngineBlock_ApplicationSingleton::getInstance()->getDiContainerRuntime()->feedbackStateHelper->setCurrentIdentityProvider($idpEntityId);

        // Verify that we know this IdP and have metadata for it.
        $cortoIdpMetadata = $this->_verifyKnownIdP(
            $idpEntityId,
            $root->hasAttribute('Destination') ? $root->getAttribute('Destination') : null
        );

        $this->logMissingDestination($root, $idpEntityId);
        $this->logEncryptedAssertionLayouts($root, $idpEntityId);

        // Check encryption layout and fill a missing Destination before typed parsing discards XML information.
        $this->assertSupportedEncryptionLayouts($root);
        $decryptionKeyPair = $this->getDefaultDecryptionKeyPair();
        $this->assertAgentDecryptionPreconditions($root, $decryptionKeyPair);
        $this->fillMissingDestination($root, $expectedDestination);

        try {
            $sspResponse = V7Response::fromXML($root);
        } catch (Exception $exception) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                $exception->getMessage(),
                EngineBlock_Exception::CODE_NOTICE,
                $exception
            );
        }

        // Make sure it has a InResponseTo (Unsolicited is not supported) but don't actually check that what it's
        // in response to is actually a message we sent quite yet.
        if ($sspResponse->getInResponseTo() === null) {
            throw new EngineBlock_Corto_Module_Bindings_UnsolicitedAssertionException(
                'Unsolicited assertion (no InResponseTo in message) not supported!'
            );
        }

        // check the IssueInstant against our own time to see if the SP's clock is getting out of sync
        $this->_checkIssueInstant(Saml2Value::timestamp($sspResponse->getIssueInstant()), 'IdP', $idpEntityId);

        // This is an initial check to validate when a signing key is in the
        // response if it's the one that's expected by EB for that IdP,
        //  so a decent error message can be shown if this is not the case.
        $this->assertKnownIdPSigningKey($cortoIdpMetadata, $root);

        $hasEncryptedAssertion = $this->query($root, './saml:EncryptedAssertion') !== [];
        if ($hasEncryptedAssertion && !$this->_featureConfiguration->isEnabled('eb.encrypted_assertions')) {
            $this->_logger->warning('Received encrypted assertion, the encrypted assertion feature is not enabled');

            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'Encrypted assertions are not supported',
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        if ($hasEncryptedAssertion && !$sspResponse->isSigned()) {
            $this->_logger->warning(
                'Received encrypted assertion without outer signature, outer signature is required'
            );

            /** @see https://github.com/OpenConext/OpenConext-engineblock/issues/116 */
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'Encrypted assertions are required to have an outer signature, but they have none',
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        $identityProvider = $this->bundleIdentityProvider($cortoIdpMetadata);

        // Error responses never pass through the success processor.
        if (!$sspResponse->isSuccess()) {
            return $this->receiveErrorResponse($sspResponse, $identityProvider, $expectedDestination, $relayState);
        }

        try {
            $verifiedResponse = EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()
                ->getSamlVerifiedResponseProcessor()
                ->process(
                    $this->bundleServiceProvider($serviceEntityId, $expectedDestination, $decryptionKeyPair),
                    $identityProvider,
                    $expectedDestination,
                    $sspResponse
                );
        } catch (Exception $exception) {
            throw $this->responseProcessingFailure($exception);
        }

        // Only the verified envelope and the validated Assertion are trusted from here on.
        $envelope = $verifiedResponse->getVerifiedEnvelope();
        $assertion = $verifiedResponse->getAssertion();
        $this->assertResponseSignatureMethodIsAllowed($verifiedResponse->getResponseSignatureMethod());
        $this->assertResponseSignatureMethodIsAllowed($verifiedResponse->getAssertionSignatureMethod());
        $inResponseTo = $this->assertVerifiedCorrelation(
            $envelope ?? $sspResponse,
            $assertion,
            $expectedDestination
        );
        $this->_server->findRequestFromRequestId($inResponseTo);
        $this->_server->consumePendingRequest($inResponseTo, $identityProvider->getEntityId(), $expectedDestination);

        // An unsigned envelope supplies no trusted fields. Construct one from validated assertion/correlation data.
        $trustedResponse = $envelope ?? new V7Response(
            id: IDValue::fromString('_' . bin2hex(random_bytes(20))),
            status: EngineBlock_Saml2_ResponseAnnotationDecorator::createStatus(['Code' => Constants::STATUS_SUCCESS]),
            issueInstant: $assertion->getIssueInstant(),
            issuer: $assertion->getIssuer(),
            inResponseTo: NCNameValue::fromString($inResponseTo),
            destination: SAMLAnyURIValue::fromString($expectedDestination),
        );
        $ebResponse = new EngineBlock_Saml2_ResponseAnnotationDecorator($trustedResponse, $relayState);
        $ebResponse->setVerifiedSignatureMethods(
            $verifiedResponse->getResponseSignatureMethod(),
            $verifiedResponse->getAssertionSignatureMethod()
        );
        $ebResponse->setAssertions([$assertion]);

        return $ebResponse;
    }

    /**
     * Checks the routed destination, any present signature and the pending request before acting on an
     * error response. The returned response carries no assertion.
     */
    private function receiveErrorResponse(
        V7Response $sspResponse,
        BundleIdentityProvider $identityProvider,
        string $expectedDestination,
        ?string $relayState
    ): EngineBlock_Saml2_ResponseAnnotationDecorator {
        if ($sspResponse->getAssertions() !== []) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'An error Response must not contain assertions'
            );
        }

        $destination = $sspResponse->getDestination()?->getValue();
        if ($destination !== $expectedDestination) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                sprintf(
                    'Destination "%s" of the error Response does not match the expected destination "%s"',
                    $destination,
                    $expectedDestination
                ),
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        $trustedResponse = $sspResponse;
        if ($sspResponse->isSigned()) {
            $this->assertResponseSignatureMethodIsAllowed($this->signatureAlgorithm($sspResponse));
            try {
                $trustedResponse = (new ResponseEnvelopeVerifier($this->_logger))->verify($sspResponse, $identityProvider);
            } catch (Exception $exception) {
                throw $this->responseProcessingFailure($exception);
            }
        }

        if ($trustedResponse->getDestination()?->getValue() !== $expectedDestination
            || $trustedResponse->getIssuer()?->getContent()->getValue() !== $identityProvider->getEntityId()
        ) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'The verified error Response does not match the expected issuer and destination'
            );
        }

        if ($trustedResponse->getInResponseTo() === null) {
            throw new EngineBlock_Corto_Module_Bindings_UnsolicitedAssertionException(
                'Unsolicited assertion (no InResponseTo in message) not supported!'
            );
        }

        $inResponseTo = $trustedResponse->getInResponseTo()->getValue();
        $originalRequest = $this->_server->findRequestFromRequestId($inResponseTo);
        $this->_server->consumePendingRequest($inResponseTo, $identityProvider->getEntityId(), $expectedDestination);

        $response = new EngineBlock_Saml2_ResponseAnnotationDecorator($trustedResponse, $relayState);
        $response->setVerifiedSignatureMethods($this->signatureAlgorithm($sspResponse), null);

        $status = $response->getStatus();
        if (isset($status['SubCode']) && $status['SubCode'] === Constants::STATUS_NO_PASSIVE) {
            // When a no passive response status was returned from the IdP, return the response back to the ACS
            return $response;
        }

        $this->_server->getLogger()->notice(
            'Received an Error Response',
            array(
                'status'            => $status['Code'],
                'substatus'         => $status['SubCode'],
                'status_message'    => $status['Message'],
            )
        );

        // If this is a transparent MFA authentication, we want to forward the error response
        $originalSpIssuer = ($originalRequest?->getIssuerValue() ?? '');
        $mfaHelper = EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()->getMfaHelper();
        if ($mfaHelper->isTransparent($originalSpIssuer, $identityProvider->getEntityId())) {
            // The AuthnFailed response is passed transparently back to the issuer
            $response->setIsTransparentErrorResponse(true);
            return $response;
        }

        $statusCodeDescription = $status['Code'];
        if (isset($status['SubCode'])) {
            $statusCodeDescription .= '/' . $status['SubCode'];
        }
        $statusCodeDescription = str_replace('urn:oasis:names:tc:SAML:2.0:status:', '', $statusCodeDescription);

        $statusMessage = !empty($status['Message']) ? $status['Message'] : self::SAML_STATUS_MESSAGE_EMPTY;

        // Throw the exception here instead of in the Corto Filters as Corto assumes the presence of an Assertion
        $exception = new EngineBlock_Corto_Exception_ReceivedErrorStatusCode(
            'Response received with Status: ' .
            $statusCodeDescription .
            ' - ' .
            $statusMessage
        );
        $exception->setFeedbackStatusCode($statusCodeDescription);
        $exception->setFeedbackStatusMessage($statusMessage);
        $exception->setResponse($response);

        throw $exception;
    }

    /**
     * Returns the InResponseTo to correlate with. Without a verified envelope, the response fields are
     * unverified: the validated Assertion must then carry the issuer, recipient and request correlation.
     */
    private function assertVerifiedCorrelation(
        V7Response $response,
        V7Assertion $assertion,
        string $expectedDestination
    ): string {
        $inResponseTo = $response->getInResponseTo()?->getValue();
        if ($inResponseTo === null) {
            throw new EngineBlock_Corto_Module_Bindings_UnsolicitedAssertionException(
                'Unsolicited assertion (no InResponseTo in message) not supported!'
            );
        }

        if ($assertion->getIssuer()->getContent()->getValue() !== $response->getIssuer()?->getContent()->getValue()) {
            throw new ResponseProcessingFailedException(
                'Response processing failed: "The Assertion Issuer does not match the Response Issuer"'
            );
        }

        $isCorrelated = false;
        foreach ($assertion->getSubject()?->getSubjectConfirmation() ?? [] as $subjectConfirmation) {
            $data = $subjectConfirmation->getSubjectConfirmationData();
            $recipient = $data?->getRecipient()?->getValue();
            $confirmedInResponseTo = $data?->getInResponseTo()?->getValue();

            if (($recipient !== null && $recipient !== $expectedDestination)
                || ($confirmedInResponseTo !== null && $confirmedInResponseTo !== $inResponseTo)
            ) {
                throw new ResponseProcessingFailedException(
                    'Response processing failed: "The SubjectConfirmation does not match the expected recipient and request"'
                );
            }

            $isCorrelated = $isCorrelated || ($recipient !== null && $confirmedInResponseTo !== null);
        }

        if (!$isCorrelated) {
            throw new ResponseProcessingFailedException(
                'Response processing failed: "A Response requires a SubjectConfirmation with Recipient and InResponseTo"'
            );
        }

        return $inResponseTo;
    }

    private function responseProcessingFailure(Exception $exception): Exception
    {
        if ($exception instanceof UnsupportedSignatureAlgorithmException) {
            return new EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException($exception->getAlgorithm());
        }

        $agentFailure = PrivateKeyAgentFailure::find($exception);
        if ($agentFailure !== null) {
            // Not chained: only the redacted agent diagnostic is kept. There is no local-key fallback.
            return new ResponseProcessingFailedException(sprintf(
                'Response processing failed: "The private key agent could not decrypt the assertion (%s)"',
                PrivateKeyAgentFailure::describe($agentFailure)
            ));
        }

        $failure = new ResponseProcessingFailedException(
            sprintf('Response processing failed: "%s"', $exception->getMessage()),
            0,
            $exception
        );

        // The clock on the IdP side must be checked
        // @see \SimpleSAML\SAML2\Assertion\Validation\ConstraintValidator\NotBefore::validate
        // @see \SimpleSAML\SAML2\Assertion\Validation\ConstraintValidator\NotOnOrAfter::validate
        if (str_contains($failure->getMessage(), 'Received an assertion that is valid in the future')
            || str_contains($failure->getMessage(), 'Received an assertion that has expired')
            || str_contains($failure->getMessage(), 'Received an assertion with a session that has expired')
        ) {
            return new EngineBlock_Corto_Module_Bindings_ClockIssueException(
                $failure->getMessage(),
                EngineBlock_Exception::CODE_ERROR,
                $failure
            );
        }

        // Passthrough, should be handled at a different level protecting against oracle attacks
        return $failure;
    }

    private function signatureAlgorithm(V7Response|V7Assertion $element): ?string
    {
        return $element->getSignature()?->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue();
    }

    private function assertResponseSignatureMethodIsAllowed(?string $algorithm): void
    {
        if ($algorithm !== null && in_array($algorithm, $this->_server->getConfig('forbiddenSignatureMethods'), true)) {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException($algorithm);
        }
    }

    protected function _receiveMessageFromInternalBinding($key)
    {
        if (!isset($this->_internalBindingMessages[$key])) {
            return false;
        }
        return $this->_internalBindingMessages[$key];
    }

    /**
     * Verify if a message has an issuer that is known as an SP to us. If not, it
     * throws a Corto_Module_Bindings_VerificationException.
     * @param string $messageIssuer
     * @return AbstractRole Remote Entity that issued the message
     * @throws EngineBlock_Exception_UnknownServiceProvider
     */
    protected function _verifyKnownSP(string $messageIssuer)
    {
        $remoteEntity = $this->_server->getRepository()->findServiceProviderByEntityId($messageIssuer);

        if ($remoteEntity) {
            return $remoteEntity;
        }

        $this->_logger->notice(
            sprintf(
                'Tried to verify a message from issuer "%s", but there is no known SP with that ID.',
                $messageIssuer
            )
        );

        throw new EngineBlock_Exception_UnknownServiceProvider(
            sprintf('Issuer "%s" is not a known remote entity? (please add SP to Remote Entities)', $messageIssuer),
            $messageIssuer
        );
    }

    /**
     * Verify if a message has an issuer that is known to us. If not, it
     * throws a Corto_Module_Bindings_VerificationException.
     * @param string $messageIssuer
     * @param string $destination
     * @return AbstractRole Remote Entity that issued the message
     * @throws EngineBlock_Exception_UnknownIdentityProvider
     */
    protected function _verifyKnownIdP($messageIssuer, $destination = '')
    {
        if ($this->stepupIdentityProvider->entityId === $messageIssuer) {
            return $this->stepupIdentityProvider;
        }

        $remoteEntity = $this->_server->getRepository()->findIdentityProviderByEntityId($messageIssuer);

        if ($remoteEntity) {
            return $remoteEntity;
        }

        $this->_logger->notice(
            sprintf(
                'Tried to verify a message from issuer "%s", but there is no known IdP entity with that ID.',
                $messageIssuer
            )
        );

        throw new EngineBlock_Exception_UnknownIdentityProvider(
            sprintf('Issuer "%s" is not a known remote entity? (please add IdP to Remote Entities)', $messageIssuer),
            $messageIssuer,
            $destination
        );
    }

    /**
     * Check if the IssueInstant of the message is too far out of sync
     * @param integer $issueInstant
     * @param string $type
     * @param string $entityid
     */
    protected function _checkIssueInstant($issueInstant, $type, $entityid)
    {
        $time = EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()->getTimeProvider()->time();
        $timeDelta = $time - $issueInstant;

        if ($type === 'SP' && $timeDelta > self::OLD_ISSUE_INSTANT_THRESHOLD_SECONDS) {
            $this->_logger->warning(
                sprintf(
                    'IssueInstant of SAMLRequest from SP "%s" is %d seconds (more than 24 hours) in the past; possible replay or severely out-of-sync SP clock',
                    $entityid,
                    $timeDelta
                )
            );
            return;
        }

        // check the IssueInstant against our own time to see if the SP's clock is getting out of sync
        // Ssp has a hard-coded limit of 60 seconds; use 30 here to catch an IdP's drifting clock early
        if (abs($timeDelta) > 30) {
            $this->_logger->notice(
                sprintf(
                    'IssueInstant of SAML message from %s "%s" is %d seconds in the %s; might indicate (local or remote) clock synchronization issues',
                    $type,
                    $entityid,
                    abs($timeDelta),
                    $timeDelta>0 ? "past" : "future"
                )
            );
        }
    }

    public function send(
        EngineBlock_Saml2_MessageAnnotationDecorator $message,
        AbstractRole $remoteEntity,
        bool $useDefaultKey = false
    ): void {
        $bindingUrn = $message->getDeliverByBinding();

        if ($bindingUrn === 'INTERNAL') {
            $this->sendInternal($message);
            return;
        }

        $mustBeSigned = $this->shouldMessageBeSigned($message->getSspMessage(), $remoteEntity);

        try {
            // The binding is checked before any key is loaded, so a rejected binding never reaches a signer.
            if ($bindingUrn === Constants::BINDING_HTTP_POST) {
                $this->sendUsingPostBinding($message, $remoteEntity, $mustBeSigned, $useDefaultKey);
                return;
            }

            if ($bindingUrn === Constants::BINDING_HTTP_REDIRECT) {
                $this->sendUsingRedirectBinding($message, $remoteEntity, $mustBeSigned, $useDefaultKey);
                return;
            }
        } catch (PrivateKeyAgentExceptionInterface $failure) {
            // Not chained: only the redacted agent diagnostic is kept. Nothing was sent and no local key is tried.
            throw new EngineBlock_Corto_Module_Bindings_Exception(
                sprintf(
                    'The private key agent could not sign the message for entity "%s" (%s)',
                    $remoteEntity->entityId,
                    PrivateKeyAgentFailure::describe($failure)
                ),
                EngineBlock_Exception::CODE_ERROR
            );
        }

        throw new EngineBlock_Corto_Module_Bindings_Exception('Unsupported Binding');
    }

    private function sendUsingPostBinding(
        EngineBlock_Saml2_MessageAnnotationDecorator $message,
        AbstractRole $remoteEntity,
        bool $mustBeSigned,
        bool $useDefaultKey
    ): void {
        $action = $message->getDestination();
        if (!isset($action)) {
            throw new EngineBlock_View_Exception('No action given to HTTP Post screen');
        }

        $type = $message->getMessageType();
        if (!isset($type)) {
            throw new EngineBlock_View_Exception('No message type (SAMLRequest or SAMLResponse) given to HTTP Post screen');
        }

        $xml = $this->serializeMessageForPostBinding(
            $message->getSspMessage(),
            $remoteEntity,
            $mustBeSigned,
            $useDefaultKey
        );

        // If the processed assertion consumer service is set on the response, it is posted back to the SP using the
        // the 'return' hidden form field.
        $return = null;
        if (method_exists($message, 'getReturn') && !empty(trim($message->getReturn() ?? ''))) {
            $return = $message->getReturn();
        }

        // RelayState is transport state kept on the EngineBlock adapter, not in the protocol element.
        $relayState = $this->outgoingRelayState($message);

        $log = $this->_server->getLogger();
        $log->info('HTTP-Post: Sending Message', array('saml_message' => $xml));

        $output = $this->twig->render(
            '@theme/Authentication/View/Proxy/form.html.twig',
            [
                'action' => $action,
                'message' => base64_encode($xml),
                'relayState' => $relayState,
                'return' => $return,
                'name' => $type,
            ]
        );
        $this->_server->sendOutput($output);
    }

    /**
     * Signs copies of the message, so the annotated message itself never carries a signer.
     */
    private function serializeMessageForPostBinding(
        V7Message $sspMessage,
        AbstractRole $remoteEntity,
        bool $mustBeSigned,
        bool $useDefaultKey
    ): string {
        if (!$mustBeSigned) {
            return Saml2Value::toXmlString($sspMessage->toXML());
        }

        [$signer, $keyInfo] = $this->createSigner($remoteEntity, $useDefaultKey);

        if ($sspMessage instanceof V7Response) {
            $signedMessage = $this->signResponse($sspMessage, $remoteEntity, $signer, $keyInfo);
        } else {
            $signedMessage = MessageRebuilder::authnRequest($sspMessage, []);
            $signedMessage->sign($signer, XmlSecurityConstants::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
        }

        return Saml2Value::toXmlString($signedMessage->toXML());
    }

    /**
     * Every assertion is signed; the outer Response only when the SP asks for it.
     */
    private function signResponse(
        V7Response $response,
        AbstractRole $remoteEntity,
        SignatureAlgorithmInterface $signer,
        KeyInfo $keyInfo
    ): V7Response {
        $assertions = [];
        foreach ($response->getAssertions() as $assertion) {
            if (!$assertion instanceof V7Assertion) {
                throw new EngineBlock_Corto_Module_Bindings_Exception(
                    sprintf('Unable to sign an outgoing assertion of type "%s"', get_class($assertion))
                );
            }

            $signedAssertion = MessageRebuilder::assertion($assertion, []);
            $signedAssertion->sign($signer, XmlSecurityConstants::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
            // saml2 signs while serializing into a detached document, so a signer set on a nested assertion is
            // lost when the Response is serialized. The parsed signed assertion is imported unchanged instead.
            $assertions[] = V7Assertion::fromXML($signedAssertion->toXML());
        }

        $signedResponse = MessageRebuilder::response($response, ['assertions' => $assertions]);
        if ($remoteEntity instanceof ServiceProvider && $remoteEntity->getCoins()->signResponse()) {
            $signedResponse->sign($signer, XmlSecurityConstants::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
        }

        return $signedResponse;
    }

    private function sendUsingRedirectBinding(
        EngineBlock_Saml2_MessageAnnotationDecorator $message,
        AbstractRole $remoteEntity,
        bool $mustBeSigned,
        bool $useDefaultKey
    ): void {
        $sspMessage = $message->getSspMessage();
        if ($sspMessage instanceof V7Response) {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedBindingException(
                'May not send a response via HTTP redirect'
            );
        }

        $destination = $message->getDestination();
        if ($destination === null || $destination === '') {
            throw new EngineBlock_Corto_Module_Bindings_Exception('No destination given for the HTTP-Redirect binding');
        }

        $relayState = $this->outgoingRelayState($message);
        if ($mustBeSigned) {
            [$signer] = $this->createSigner($remoteEntity, $useDefaultKey);
            $query = BundleAuthnRequest::createNew($sspMessage, $signer, $relayState)->buildRequestQuery();
        } else {
            $query = $this->getUnsignedRedirectEncoder()->buildQuery(
                BundleAuthnRequest::createNew($sspMessage),
                $relayState
            );
        }

        $url = $destination . (str_contains($destination, '?') ? '&' : '?') . $query;
        if ($remoteEntity instanceof IdentityProvider) {
            $domainHint = $remoteEntity->getCoins()->azureDomainHint();
            if (!empty($domainHint)) {
                $url .= '&' . http_build_query(['whr' => $domainHint]);
            }
        }

        $this->_server->redirect($url, $message);
    }

    /**
     * Only an absent or empty RelayState is omitted; falsy values such as "0" are opaque SP state.
     */
    private function outgoingRelayState(EngineBlock_Saml2_MessageAnnotationDecorator $message): ?string
    {
        $relayState = $message->getRelayState();

        return $relayState === null || $relayState === '' ? null : $relayState;
    }

    protected function shouldMessageBeSigned(V7Message $sspMessage, AbstractRole $remoteEntity)
    {
        if ($sspMessage instanceof V7Response) {
            return true;
        }

        if (!$sspMessage instanceof V7AuthnRequest) {
            throw new EngineBlock_Corto_Module_Bindings_Exception(
                sprintf('Unsupported Message type: "%s"', get_class($sspMessage))
            );
        }

        // Determine if we should sign the message
        return $remoteEntity->requestsMustBeSigned || $this->_server->getConfig('WantsAuthnRequestsSigned');
    }

    /**
     * Selects the route key, or the default key when forced, with the signature method configured for the
     * remote entity. An unsupported method is rejected; another method is never substituted. An agent key pair
     * signs through the private key agent with its certificate; no local private key is loaded for it.
     *
     * @return array{SignatureAlgorithmInterface, KeyInfo}
     */
    private function createSigner(AbstractRole $remoteEntity, bool $useDefaultKey): array
    {
        $keyPair = $this->_server->getSigningCertificates($useDefaultKey);
        $signatureMethod = $remoteEntity->getCoins()->signatureMethod();

        try {
            $signer = $keyPair->usesPrivateKeyAgent()
                ? $this->getSignerFactory()->forAgentCertificate(
                    new XmlSecurityCertificate(PEM::fromString($keyPair->getCertificate()->toPem())),
                    $signatureMethod
                )
                : $this->getSignerFactory()->forLocalKey(
                    XmlSecurityPrivateKey::fromFile($keyPair->getPrivateKey()->filePath()),
                    $signatureMethod
                );
        } catch (UnsupportedSignatureAlgorithmException $exception) {
            throw EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException::forRemoteEntity(
                $exception->getAlgorithm(),
                $remoteEntity->entityId,
                $exception
            );
        }

        $keyInfo = new KeyInfo([
            new X509Data([
                new X509CertificateElement(Base64BinaryValue::fromString($keyPair->getCertificate()->toCertData())),
            ]),
        ]);

        return [$signer, $keyInfo];
    }

    private function getSignerFactory(): SignerFactory
    {
        return EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()->getSamlSignerFactory();
    }

    private function getUnsignedRedirectEncoder(): UnsignedRedirectEncoder
    {
        return EngineBlock_ApplicationSingleton::getInstance()->getDiContainer()->getSamlUnsignedRedirectEncoder();
    }

    private function assertValidAcsLocationScheme($acsLocation)
    {
        if ($acsLocation && !$this->acsLocationSchemeValidator->validate($acsLocation)) {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedAcsLocationSchemeException(
                'The received ACS location does not have a valid scheme'
            );
        }
    }

    /**
     * See if the given binding is supported by EngineBlock
     *
     * @param string $binding
     * @return bool
     */
    public function isSupportedBinding($binding)
    {
        return (isset($this->_bindings[$binding]));
    }

    public function sendInternal(EngineBlock_Saml2_MessageAnnotationDecorator $message)
    {
        // Store the message
        $name = $message->getMessageType();
        $this->_internalBindingMessages[$name] = $message;

        $destinationLocation = $message->getDestination();
        $parameters = $this->_server->getParametersFromUrl($destinationLocation);
        if (isset($parameters['RemoteIdPMd5'])) {
            $this->_server->setRemoteIdpMd5($parameters['RemoteIdPMd5']);
        }

        $log = $this->_server->getLogger();
        $log->info("Using internal binding for destination $destinationLocation", array('url_params' => $parameters));

        $serviceName = $parameters['ServiceName'];

        $log->info("Calling service '$serviceName'");
        $this->_server->getServicesModule()->serve($serviceName);
        $log->info("Done calling service '$serviceName'");
    }

    /**
     * @param $key
     * @param $message
     * @return $this
     */
    public function registerInternalBindingMessage($key, $message)
    {
        $this->_internalBindingMessages[$key] = $message;
        return $this;
    }

    /**
     * Only EngineBlock's default key decrypts received assertions, independent of the route key of the original
     * request. A local default key exposes only its own private key; an agent default key exposes none and marks
     * the service provider as using the agent, whose decryption candidates are limited to the default certificate.
     */
    private function bundleServiceProvider(
        string $serviceEntityId,
        string $expectedDestination,
        EngineBlock_X509_KeyPair $keyPair
    ): BundleServiceProvider {
        $configuration = [
            'entityId' => $serviceEntityId,
            'assertionConsumerUrl' => $expectedDestination,
            'keys' => [
                [
                    'type' => 'X509Certificate',
                    'signing' => true,
                    'encryption' => false,
                    'X509Certificate' => $keyPair->getCertificate()->toCertData(),
                ],
            ],
        ];

        if ($keyPair->usesPrivateKeyAgent()) {
            $configuration['privateKeyAgent'] = true;

            return new BundleServiceProvider($configuration);
        }

        $privateKey = $keyPair->getPrivateKey();
        if ($privateKey) {
            $configuration['privateKeys'] = [
                new Saml2PrivateKey($privateKey->filePath(), Saml2PrivateKey::NAME_DEFAULT),
            ];
        }

        return new BundleServiceProvider($configuration);
    }

    private function getDefaultDecryptionKeyPair(): EngineBlock_X509_KeyPair
    {
        return $this->_server->getSigningCertificates(true);
    }

    private function bundleIdentityProvider(IdentityProvider $identityProvider): BundleIdentityProvider
    {
        /** @var EngineBlock_X509_Certificate[] $certificates */
        $certificates = $identityProvider->certificates;

        return new BundleIdentityProvider([
            'entityId' => $identityProvider->entityId,
            'keys' => array_values(array_map(
                static fn(EngineBlock_X509_Certificate $certificate) => [
                    'type' => 'X509Certificate',
                    'signing' => true,
                    'X509Certificate' => $certificate->toCertData(),
                ],
                $certificates
            )),
        ]);
    }

    private function decodePostedMessage(EngineBlock_Http_Request $httpRequest, string $parameter): string
    {
        $encoded = $httpRequest->getPostParameter($parameter);
        if (!is_string($encoded) || $encoded === '') {
            throw new EngineBlock_Corto_Module_Bindings_UnsupportedBindingException(
                sprintf('Missing %s parameter in the HTTP-POST request', $parameter),
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        $xml = base64_decode($encoded, true);
        if ($xml === false || $xml === '') {
            throw new EngineBlock_Corto_Module_Bindings_UnableToReceiveMessageException(
                sprintf('The %s parameter is not valid base64', $parameter),
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        return $xml;
    }

    private function postedRelayState(EngineBlock_Http_Request $httpRequest): ?string
    {
        $relayState = $httpRequest->getPostParameter('RelayState');

        return is_string($relayState) ? $relayState : null;
    }

    private static function isElement(Element $element, string $namespace, string $localName): bool
    {
        return $element->namespaceURI === $namespace && $element->localName === $localName;
    }

    /**
     * @return list<Dom\Node>
     */
    private function query(Element $context, string $expression): array
    {
        $xpath = new XPath($context->ownerDocument);
        $xpath->registerNamespace('samlp', Constants::NS_SAMLP);
        $xpath->registerNamespace('saml', Constants::NS_SAML);
        $xpath->registerNamespace('ds', Constants::NS_XDSIG);
        $xpath->registerNamespace('xenc', Constants::NS_XENC);
        $xpath->registerNamespace('xenc11', XmlSecurityConstants::NS_XENC11);

        return iterator_to_array($xpath->query($expression, $context), false);
    }

    /**
     * Every EncryptedAssertion must carry exactly one EncryptedKey, inline in the KeyInfo of its
     * EncryptedData, and no RetrievalMethod. Checked on the received XML, as parsing drops sibling keys.
     */
    private function assertSupportedEncryptionLayouts(Element $root): void
    {
        foreach ($this->query($root, './saml:EncryptedAssertion') as $encryptedAssertion) {
            $allKeys = $this->query($encryptedAssertion, './/xenc:EncryptedKey');
            $inlineKeys = $this->query($encryptedAssertion, './xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey');
            $retrievalMethods = $this->query($encryptedAssertion, './/ds:RetrievalMethod');

            if (count($allKeys) !== 1 || count($inlineKeys) !== 1 || $retrievalMethods !== []) {
                throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                    'Unsupported EncryptedAssertion layout: exactly one EncryptedKey inside the KeyInfo of the '
                    . 'EncryptedData is required',
                    EngineBlock_Exception::CODE_NOTICE
                );
            }
        }
    }

    /**
     * Enforces default-only decryption and supported key transport before any private key agent call.
     *
     * Every certificate an EncryptedKey names must be the default decryption certificate: a hint for any other
     * certificate is rejected, even next to the default one. Key transport is limited to RSA-OAEP with parameters
     * the agent mapping handles. xml-security asks the agent for SHA-256 when xmlenc11#rsa-oaep has no DigestMethod
     * or MGF, while the default is SHA-1, so that form is rejected instead of sending a guessed digest. Local
     * decryption is unaffected.
     */
    private function assertAgentDecryptionPreconditions(Element $root, EngineBlock_X509_KeyPair $decryptionKeyPair): void
    {
        $encryptedKeys = $this->query($root, './saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey');
        if ($encryptedKeys === [] || !$decryptionKeyPair->usesPrivateKeyAgent()) {
            return;
        }

        $defaultCertificate = base64_decode($decryptionKeyPair->getCertificate()->toCertData(), true);
        foreach ($encryptedKeys as $encryptedKey) {
            foreach ($this->query($encryptedKey, './ds:KeyInfo//ds:X509Certificate') as $namedCertificate) {
                $certificate = base64_decode(preg_replace('/\s+/', '', $namedCertificate->textContent) ?? '', true);
                if (!is_string($certificate) || !hash_equals((string) $defaultCertificate, $certificate)) {
                    throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                        'The EncryptedKey names a certificate other than the default decryption certificate',
                        EngineBlock_Exception::CODE_NOTICE
                    );
                }
            }
        }

        foreach ($encryptedKeys as $encryptedKey) {
            $algorithm = $this->getEncryptionMethodAlgorithm($encryptedKey);
            if ($algorithm === XmlSecurityConstants::KEY_TRANSPORT_OAEP_MGF1P) {
                continue;
            }

            if ($algorithm !== XmlSecurityConstants::KEY_TRANSPORT_OAEP) {
                throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                    sprintf('Key transport algorithm "%s" is not supported with the private key agent', $algorithm),
                    EngineBlock_Exception::CODE_NOTICE
                );
            }

            $hasDigest = $this->query($encryptedKey, './xenc:EncryptionMethod/ds:DigestMethod') !== [];
            $hasMgf = $this->query($encryptedKey, './xenc:EncryptionMethod/xenc11:MGF') !== [];
            if (!$hasDigest || !$hasMgf) {
                throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                    'Key transport "' . XmlSecurityConstants::KEY_TRANSPORT_OAEP . '" requires explicit DigestMethod '
                    . 'and MGF parameters with the private key agent',
                    EngineBlock_Exception::CODE_NOTICE
                );
            }
        }
    }

    /**
     * EngineBlock allows a missing Destination only on unsigned responses, where filling in the
     * expected destination changes no signed content. A present Destination is never changed.
     */
    private function fillMissingDestination(Element $root, string $expectedDestination): void
    {
        if ($root->hasAttribute('Destination')) {
            return;
        }

        if ($this->query($root, './ds:Signature') !== []) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'Signed Response has no Destination',
                EngineBlock_Exception::CODE_NOTICE
            );
        }

        $root->setAttribute('Destination', $expectedDestination);
    }

    /**
     * Rollout diagnostics: the issuer and signature presence come from unverified XML.
     */
    private function logMissingDestination(Element $root, string $issuer): void
    {
        if ($root->hasAttribute('Destination')) {
            return;
        }

        $this->_logger->notice(
            'Received Response without Destination',
            [
                'issuer' => $issuer,
                'response_signed' => $this->query($root, './ds:Signature') !== [],
            ]
        );
    }

    /**
     * Rollout diagnostics: the issuer, algorithms and key layout come from unverified XML.
     * The layout describes the KeyInfo of the EncryptedData; keys outside it are rejected
     * separately. Never use the layout label to decide acceptance.
     */
    private function logEncryptedAssertionLayouts(Element $root, string $issuer): void
    {
        foreach ($this->query($root, './saml:EncryptedAssertion/xenc:EncryptedData') as $encryptedData) {
            $encryptedKeys = $this->query($encryptedData, './ds:KeyInfo/xenc:EncryptedKey');
            $retrievalMethods = $this->query($encryptedData, './ds:KeyInfo/ds:RetrievalMethod');

            $keyLayout = match (true) {
                count($retrievalMethods) > 0 => 'retrieval-method',
                count($encryptedKeys) > 1 => 'multiple-keys-in-key-info',
                count($encryptedKeys) === 1 => 'single-key-in-key-info',
                default => 'no-key-in-key-info',
            };

            $this->_logger->notice(
                'Received encrypted Assertion',
                [
                    'issuer' => $issuer,
                    'content_encryption_algorithm' => $this->getEncryptionMethodAlgorithm($encryptedData),
                    'key_transport_algorithms' => array_map(
                        fn(Element $encryptedKey) => $this->getEncryptionMethodAlgorithm($encryptedKey),
                        $encryptedKeys
                    ),
                    'key_layout' => $keyLayout,
                ]
            );
        }
    }

    private function getEncryptionMethodAlgorithm(Element $element): ?string
    {
        $algorithm = $this->query($element, './xenc:EncryptionMethod/@Algorithm');

        return $algorithm === [] ? null : $algorithm[0]->value;
    }

    /**
     * This is an initial check to validate when a signing key is in the
     * response, if it's the one that's expected by EB for that IdP,
     * so a decent error message can be shown if this is not the case.
     */
    private function assertKnownIdPSigningKey(IdentityProvider $metadata, Element $root): void {
        $certificates = array_map(
            static fn(Dom\Node $certificate) => preg_replace('/\s+/', '', $certificate->textContent),
            $this->query($root, './ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
        );

        // If no key is in the response we don't need to validate if it's known because the
        // validation if the signature is present is the responsibility of the response processor.
        if (count($certificates) === 0) {
            return;
        }

        if (count($certificates) > 1) {
            $this->_logger->notice(
                sprintf(
                    'Tried to verify a message from issuer "%s", but requests with multiple signing keys are not supported.',
                    $metadata->entityId
                )
            );

            throw new EngineBlock_Corto_Module_Bindings_Exception(sprintf('Multiple signing keys supplied for issuer: %s', $metadata->entityId));
        }

        foreach ($metadata->certificates as $metaDataCertificate) {
            if ($metaDataCertificate->toCertData() === $certificates[0]) {
                return;
            }
        }

        $this->_logger->notice(
            sprintf(
                'Tried to verify a message from issuer "%s", but the expected signing key does not match.',
                $metadata->entityId
            )
        );

        throw new EngineBlock_Corto_Exception_UnknownIdentityProviderSigningKey('Unknown signing key supplied for issuer', $metadata->entityId);
    }
}
