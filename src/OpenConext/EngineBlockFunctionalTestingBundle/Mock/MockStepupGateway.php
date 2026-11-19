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

namespace OpenConext\EngineBlockFunctionalTestingBundle\Mock;

use DateInterval;
use DateTime;
use EngineBlock_ApplicationSingleton;
use EngineBlock_Saml2_AuthnRequestAnnotationDecorator;
use EngineBlock_Saml2_ResponseAnnotationDecorator;
use LogicException;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use OpenConext\EngineBlockFunctionalTestingBundle\Fixtures\FunctionalTestingStepupGatewayMockConfiguration;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\HttpBinding;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\Response;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\XmlSecurity;
use RuntimeException;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\EntityIDValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\Audience;
use SimpleSAML\SAML2\XML\saml\AudienceRestriction;
use SimpleSAML\SAML2\XML\saml\AuthenticatingAuthority;
use SimpleSAML\SAML2\XML\saml\AuthnContext;
use SimpleSAML\SAML2\XML\saml\AuthnContextClassRef;
use SimpleSAML\SAML2\XML\saml\AuthnStatement;
use SimpleSAML\SAML2\XML\saml\Conditions;
use SimpleSAML\SAML2\XML\saml\Subject;
use SimpleSAML\SAML2\XML\saml\SubjectConfirmation;
use SimpleSAML\SAML2\XML\saml\SubjectConfirmationData;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Response as SamlResponse;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSchema\Type\NCNameValue;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class MockStepupGateway
{

    const PARAMETER_REQUEST = 'SAMLRequest';
    const PARAMETER_RELAY_STATE = 'RelayState';
    const PARAMETER_SIGNATURE = 'Signature';
    const PARAMETER_SIGNATURE_ALGORITHM = 'SigAlg';

    /**
     * @var DateTime
     */
    private $currentTime;

    /**
     * @var FunctionalTestingStepupGatewayMockConfiguration
     */
    private $gatewayConfiguration;

    /**
     * @var string
     */
    private $sfoRolloverEntityId;

    /**
     * @param FunctionalTestingStepupGatewayMockConfiguration $gatewayConfiguration
     * @throws \Exception
     */
    public function __construct(
        FunctionalTestingStepupGatewayMockConfiguration $gatewayConfiguration,
        $sfoRolloverEntityId,
        private readonly EngineBlock_ApplicationSingleton $application
    ) {
        $this->gatewayConfiguration = $gatewayConfiguration;
        $this->currentTime = new DateTime();
        $this->sfoRolloverEntityId = $sfoRolloverEntityId;
    }

    /**
     * @param Request $request
     * @param string $fullRequestUri
     * @param bool $updateAudience [default] false
     * @return Response
     */
    public function handleSsoSuccess(Request $request, $fullRequestUri, $updateAudience = false)
    {
        // parse the authnRequest
        $authnRequest = $this->parseRequest($request, $fullRequestUri);

        // get parameters from authnRequest
        $nameId = $authnRequest->getNameId()->getContent()->getValue();
        $destination = $authnRequest->getAssertionConsumerServiceURL();
        $authnContextClassRef = current($authnRequest->getRequestedAuthnContext()['AuthnContextClassRef']);
        $requestId = $authnRequest->getId();

        // handle success
        return $this->createSecondFactorOnlyResponse(
            $nameId,
            $destination,
            $authnContextClassRef,
            $requestId,
            $updateAudience
        );
    }

    /**
     * @param Request $request
     * @param string $fullRequestUri
     * @return Response
     */
    public function handleSsoSuccessLoa2(Request $request, $fullRequestUri)
    {
        // parse the authnRequest
        $authnRequest = $this->parseRequest($request, $fullRequestUri);

        // get parameters from authnRequest
        $nameId = $authnRequest->getNameId()->getContent()->getValue();
        $destination = $authnRequest->getAssertionConsumerServiceURL();
        $authnContextClassRef = 'https://gateway.tld/authentication/loa2';
        $requestId = $authnRequest->getId();

        // handle success
        return $this->createSecondFactorOnlyResponse(
            $nameId,
            $destination,
            $authnContextClassRef,
            $requestId
        );
    }

    /**
     * @param Request $request
     * @param string $fullRequestUri
     * @param string $status
     * @param string $subStatus
     * @param string $message
     * @return Response
     */
    public function handleSsoFailure(Request $request, $fullRequestUri, $status, $subStatus, $message = '')
    {
        // parse the authnRequest
        $authnRequest = $this->parseRequest($request, $fullRequestUri);

        // get parameters from authnRequest
        $destination = $authnRequest->getAssertionConsumerServiceURL();
        $requestId = $authnRequest->getId();

        return $this->createFailureResponse($destination, $requestId, $status, $subStatus, $message);
    }


    /**
     * @param string $nameId
     * @param string $destination The ACS location
     * @param string|null $authnContextClassRef The loa level
     * @param string $requestId The requestId
     * @param bool $updateAudience [default] false
     * @return Response
     */
    private function createSecondFactorOnlyResponse($nameId, $destination, $authnContextClassRef, $requestId, $updateAudience = false)
    {
        return $this->createNewAuthnResponse(
            $this->createNewAssertion(
                $nameId,
                $authnContextClassRef,
                $destination,
                $requestId,
                $updateAudience
            ),
            $destination,
            $requestId
        );
    }

    /**
     * @param string $samlRequest
     * @param string $fullRequestUri
     * @return EngineBlock_Saml2_AuthnRequestAnnotationDecorator
     * @throws \Exception
     */
    private function parseRequest(Request $request, $fullRequestUri)
    {
        // the GET parameter is already urldecoded by Symfony, so we should not do it again.
        $requestData = $request->query->getString(self::PARAMETER_REQUEST);
        $samlRequest = base64_decode($requestData, true);
        if ($samlRequest === false) {
            throw new BadRequestHttpException('Failed decoding the request, did not receive a valid base64 string');
        }

        // Catch any errors gzinflate triggers
        $errorNo = $errorMessage = null;
        set_error_handler(function ($number, $message) use (&$errorNo, &$errorMessage): void {
            $errorNo      = $number;
            $errorMessage = $message;
        });
        $samlRequest = gzinflate($samlRequest);
        restore_error_handler();

        if ($samlRequest === false) {
            throw new BadRequestHttpException(sprintf(
                'Failed inflating the request; error "%d": "%s"',
                $errorNo,
                $errorMessage
            ));
        }

        // 1. Parse to xml object
        $document = DOMDocumentFactory::fromString($samlRequest);

        // 2. Parse saml request
        if ($document->documentElement?->localName !== 'AuthnRequest') {
            throw new RuntimeException(sprintf(
                'The received request is not an AuthnRequest, "%s" received instead',
                $document->documentElement?->localName
            ));
        }
        $authnRequest = new EngineBlock_Saml2_AuthnRequestAnnotationDecorator(
            AuthnRequest::fromXML($document->documentElement)
        );

        // 3. Validate destination
        if ($authnRequest->getDestination() !== $fullRequestUri) {
            throw new BadRequestHttpException(sprintf(
                'Actual Destination "%s" does not match the AuthnRequest Destination "%s"',
                $fullRequestUri,
                $authnRequest->getDestination()
            ));
        }

        // 4. Validate issuer
        $features = $this->application->getDiContainer()->getFeatureConfiguration();
        $expectedIssuer = $features->isEnabled('eb.stepup.sfo.override_engine_entityid')
            ? $this->sfoRolloverEntityId
            : $this->gatewayConfiguration->getServiceProviderEntityId();
        if ($expectedIssuer !== $authnRequest->getIssuerValue()) {
            throw new BadRequestHttpException(sprintf(
                'Actual issuer "%s" does not match the AuthnRequest Issuer "%s"',
                $expectedIssuer,
                $authnRequest->getIssuerValue()
            ));
        }

        // 5. Validate the signature of the query (SAML bindings 3.4.4.1)
        // The query string to validate needs to be urlencoded again because Symfony has already decoded this for us
        $query = self::PARAMETER_REQUEST . '=' . urlencode($requestData);
        $query .= '&' . self::PARAMETER_SIGNATURE_ALGORITHM . '=' . urlencode($request->query->getString(self::PARAMETER_SIGNATURE_ALGORITHM));

        $signature = base64_decode($request->query->getString(self::PARAMETER_SIGNATURE));

        // EngineBlock signs Stepup requests with its default key. The mock's key signs only its responses.
        $keys = $this->application->getDiContainer()->getEncryptionKeysConfiguration();
        $certificate = file_get_contents($keys['default']['publicFile']);
        if ($certificate === false) {
            throw new RuntimeException('Unable to read the EngineBlock signing certificate');
        }
        if (!XmlSecurity::verifyRedirectSignature(
            $query,
            $signature,
            $certificate,
            Constants::SIG_RSA_SHA256
        )) {
            throw new BadRequestHttpException(
                'Validation of the signature in the AuthnRequest failed'
            );
        }

        return $authnRequest;
    }

    /**
     * @param Response $response
     * @return string
     */
    public function parsePostResponse(Response $response)
    {
        return $response->toXml();
    }

    /**
     * @param string $destination The ACS location
     * @param string $requestId The requestId
     * @param string $status The response status (see \SimpleSAML\SAML2\Constants)
     * @param string|null $subStatus An optional substatus (see \SimpleSAML\SAML2\Constants)
     * @param string|null $message The textual message
     * @return Response
     */
    private function createFailureResponse($destination, $requestId, $status, $subStatus = null, $message = null)
    {
        if (!$this->isValidResponseStatus($status)) {
            throw new LogicException(sprintf('Trying to set invalid Response Status'));
        }

        if ($subStatus && !$this->isValidResponseSubStatus($subStatus)) {
            throw new LogicException(sprintf('Trying to set invalid Response SubStatus'));
        }

        $status = ['Code' => $status];
        if ($subStatus) {
            $status['SubCode'] = $subStatus;
        }
        if ($message) {
            $status['Message'] = $message;
        }

        return new Response($this->createSamlResponse($destination, $requestId, $status, []));
    }

    private function createSamlResponse($destination, $requestId, array $status, array $assertions): SamlResponse
    {
        return new SamlResponse(
            id: IDValue::fromString(HttpBinding::generateId()),
            status: EngineBlock_Saml2_ResponseAnnotationDecorator::createStatus($status),
            issueInstant: Saml2Value::dateTime($this->getTimestamp()),
            issuer: Saml2Value::issuer($this->gatewayConfiguration->getIdentityProviderEntityId()),
            inResponseTo: NCNameValue::fromString($requestId),
            destination: $destination === null ? null : SAMLAnyURIValue::fromString($destination),
            assertions: $assertions,
        );
    }

    /**
     * @param Assertion $newAssertion
     * @param string $destination The ACS location
     * @param string $requestId The requestId
     * @return Response
     */
    private function createNewAuthnResponse(Assertion $newAssertion, $destination, $requestId)
    {
        $response = new Response(
            $this->createSamlResponse($destination, $requestId, ['Code' => Constants::STATUS_SUCCESS], [$newAssertion])
        );

        return $this->signAssertion($response);
    }

    /**
     * @param string $nameId
     * @param string $authnContextClassRef
     * @param string $destination The ACS location
     * @param string $requestId The requestId
     * @param bool $updateAudience [default] false
     * @return Assertion
     */
    private function createNewAssertion($nameId, $authnContextClassRef, $destination, $requestId, $updateAudience = false)
    {
        $notOnOrAfter = Saml2Value::dateTime($this->getTimestamp('PT5M'));
        $audience = $this->gatewayConfiguration->getServiceProviderEntityId();
        // If the entity id being updated, then set that new EntityId as the audience for this assertion
        if ($updateAudience) {
            $audience = $this->sfoRolloverEntityId;
        }

        return new Assertion(
            issuer: Saml2Value::issuer($this->gatewayConfiguration->getIdentityProviderEntityId()),
            issueInstant: Saml2Value::dateTime($this->getTimestamp()),
            id: IDValue::fromString(HttpBinding::generateId()),
            subject: new Subject(
                Saml2Value::nameId($nameId, Constants::NAMEID_UNSPECIFIED),
                [$this->createSubjectConfirmation($destination, $requestId, $notOnOrAfter)]
            ),
            conditions: new Conditions(
                notBefore: Saml2Value::dateTime($this->currentTime->getTimestamp()),
                notOnOrAfter: $notOnOrAfter,
                audienceRestriction: [
                    new AudienceRestriction([new Audience(SAMLAnyURIValue::fromString($audience))]),
                ],
            ),
            statements: [$this->createAuthenticationStatement($authnContextClassRef)],
        );
    }

    /**
     * @param string $destination The ACS location
     * @param string $requestId The requestId
     */
    private function createSubjectConfirmation($destination, $requestId, $notOnOrAfter): SubjectConfirmation
    {
        return new SubjectConfirmation(
            SAMLAnyURIValue::fromString(Constants::CM_BEARER),
            null,
            new SubjectConfirmationData(
                notOnOrAfter: $notOnOrAfter,
                recipient: $destination === null ? null : EntityIDValue::fromString($destination),
                inResponseTo: NCNameValue::fromString($requestId),
            ),
        );
    }

    /**
     * @param string|null $authnContextClassRef
     */
    private function createAuthenticationStatement($authnContextClassRef): AuthnStatement
    {
        return new AuthnStatement(
            new AuthnContext(
                $authnContextClassRef ? new AuthnContextClassRef(SAMLAnyURIValue::fromString($authnContextClassRef)) : null,
                null,
                null,
                [
                    new AuthenticatingAuthority(
                        EntityIDValue::fromString($this->gatewayConfiguration->getIdentityProviderEntityId())
                    ),
                ],
            ),
            Saml2Value::dateTime($this->getTimestamp()),
        );
    }

    /**
     * @param string $interval a DateInterval compatible interval to skew the time with
     * @return int
     */
    private function getTimestamp($interval = null)
    {
        $time = clone $this->currentTime;

        if ($interval) {
            $time->add(new DateInterval($interval));
        }

        return $time->getTimestamp();
    }

    private function signAssertion(Response $response): Response
    {
        return $response->setAssertionSigner(
            XmlSecurity::signer($this->gatewayConfiguration->getIdentityProviderGetPrivateKeyPem()),
            XmlSecurity::keyInfo($this->gatewayConfiguration->getIdentityProviderPublicKeyCertData())
        );
    }

    private function isValidResponseStatus($status)
    {
        return in_array($status, [
            Constants::STATUS_SUCCESS,            // weeee!
            Constants::STATUS_REQUESTER,          // Something is wrong with the AuthnRequest
            Constants::STATUS_RESPONDER,          // Something went wrong with the Response
            Constants::STATUS_VERSION_MISMATCH,   // The version of the request message was incorrect
        ]);
    }

    private function isValidResponseSubStatus($subStatus)
    {
        return in_array($subStatus, [
            Constants::STATUS_AUTHN_FAILED,               // failed authentication
            Constants::STATUS_INVALID_ATTR,
            Constants::STATUS_INVALID_NAMEID_POLICY,
            Constants::STATUS_NO_AUTHN_CONTEXT,           // insufficient Loa or Loa cannot be met
            Constants::STATUS_NO_AVAILABLE_IDP,
            Constants::STATUS_NO_PASSIVE,
            Constants::STATUS_NO_SUPPORTED_IDP,
            Constants::STATUS_PARTIAL_LOGOUT,
            Constants::STATUS_PROXY_COUNT_EXCEEDED,
            Constants::STATUS_REQUEST_DENIED,
            Constants::STATUS_REQUEST_UNSUPPORTED,
            Constants::STATUS_REQUEST_VERSION_DEPRECATED,
            Constants::STATUS_REQUEST_VERSION_TOO_HIGH,
            Constants::STATUS_REQUEST_VERSION_TOO_LOW,
            Constants::STATUS_RESOURCE_NOT_RECOGNIZED,
            Constants::STATUS_TOO_MANY_RESPONSES,
            Constants::STATUS_UNKNOWN_ATTR_PROFILE,
            Constants::STATUS_UNKNOWN_PRINCIPAL,
            Constants::STATUS_UNSUPPORTED_BINDING,
        ]);
    }
}
