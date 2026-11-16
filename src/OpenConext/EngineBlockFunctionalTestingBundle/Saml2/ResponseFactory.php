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

namespace OpenConext\EngineBlockFunctionalTestingBundle\Saml2;

use EngineBlock_Saml2_AuthnRequestAnnotationDecorator;
use OpenConext\EngineBlock\Saml2\Message\MessageRebuilder;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use OpenConext\EngineBlockFunctionalTestingBundle\Mock\MockIdentityProvider;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\Conditions;
use SimpleSAML\SAML2\XML\saml\Subject;
use SimpleSAML\SAML2\XML\saml\SubjectConfirmation;
use SimpleSAML\SAML2\XML\saml\SubjectConfirmationData;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SamlAuthnRequest;
use SimpleSAML\SAML2\Type\SAMLDateTimeValue;
use SimpleSAML\XMLSchema\Type\NCNameValue;

class ResponseFactory
{
    /**
     * Create the Response of the mock IdP to the given AuthnRequest, based on the mock IdP's template Response.
     */
    public function createForEntityWithRequest(
        MockIdentityProvider $mockIdp,
        SamlAuthnRequest|EngineBlock_Saml2_AuthnRequestAnnotationDecorator $request
    ): Response {
        if ($request instanceof EngineBlock_Saml2_AuthnRequestAnnotationDecorator) {
            $request = $request->getSspMessage();
        }

        // Note that we expect the Mock IdP to always have a 'template' Response.
        $response = $mockIdp->getResponse();

        if ($mockIdp->shouldOmitInResponseTo()) {
            $response->setInResponseTo(null);
        } else {
            $this->setResponseReferencesToRequest($request, $response);
        }

        $this->setResponseStatus($mockIdp, $response);

        $this->setResponseSignatureKey($mockIdp, $response);

        $this->setResponseIssuer($mockIdp, $response);

        if ($mockIdp->getAuthnContextClassRef() !== null) {
            $response->setAuthnContextClassRef($mockIdp->getAuthnContextClassRef());
        }

        $this->encryptAssertions($mockIdp, $response);

        if ($mockIdp->shouldNotSendAssertions()) {
            $response->setAssertions([]);
        }

        if ($mockIdp->shouldTurnBackTheTime()) {
            // Set the timestamp to Unix Epoch
            $this->setConditionsTimes($response, notOnOrAfter: Saml2Value::dateTime(0));
        }

        if ($mockIdp->isFromTheFuture()) {
            // Set the timestamp to current time + 1 year
            $this->setConditionsTimes($response, notBefore: Saml2Value::dateTime(strtotime('+1 year')));
        }

        return $response;
    }

    private function setResponseReferencesToRequest(SamlAuthnRequest $request, Response $response): void
    {
        $requestId = $request->getId()->getValue();
        $response->setInResponseTo($requestId);

        $assertions = $response->getAssertions();
        if (!isset($assertions[0]) || !$assertions[0] instanceof Assertion) {
            return;
        }

        $subject = $assertions[0]->getSubject();
        if ($subject === null) {
            return;
        }

        $subjectConfirmations = array_map(
            static function (SubjectConfirmation $subjectConfirmation) use ($requestId): SubjectConfirmation {
                $data = $subjectConfirmation->getSubjectConfirmationData();
                return new SubjectConfirmation(
                    $subjectConfirmation->getMethod(),
                    $subjectConfirmation->getIdentifier(),
                    new SubjectConfirmationData(
                        $data?->getNotBefore(),
                        $data?->getNotOnOrAfter(),
                        $data?->getRecipient(),
                        NCNameValue::fromString($requestId),
                        $data?->getAddress(),
                        $data?->getElements() ?? [],
                        $data?->getAttributesNS() ?? [],
                    ),
                );
            },
            $subject->getSubjectConfirmation()
        );

        $response->setAssertion(MessageRebuilder::assertion($assertions[0], [
            'subject' => new Subject($subject->getIdentifier(), $subjectConfirmations),
        ]));
    }

    private function setResponseStatus(MockIdentityProvider $mockIdp, Response $response): void
    {
        $responseStatus = $response->getStatus();

        $statusOverride = [];
        $mockIdpTopStatusCode = $mockIdp->getStatusCodeTop();
        $mockIdpSubStatusCode = $mockIdp->getStatusCodeSecond();
        $mockIdpStatusMessage = $mockIdp->getStatusMessage();

        $statusOverride['Code'] = $mockIdpTopStatusCode;

        if (!empty($mockIdpSubStatusCode)) {
            $statusOverride['SubCode'] = $mockIdpSubStatusCode;
        } else {
            $statusOverride['SubCode'] = $responseStatus['SubCode'];
        }

        if ($mockIdpStatusMessage !== null) {
            $statusOverride['Message'] = $mockIdpStatusMessage;
        } elseif ($responseStatus['Message'] !== null) {
            $statusOverride['Message'] = $responseStatus['Message'];
        }

        $response->setStatus($statusOverride);
    }

    private function setResponseSignatureKey(MockIdentityProvider $mockIdp, Response $response): void
    {
        $signer = XmlSecurity::signer($mockIdp->getPrivateKeyPem(), $mockIdp->getSignatureMethod());

        if ($mockIdp->mustSignResponses()) {
            $response->setResponseSigner($signer);
        }

        if ($mockIdp->mustSignAssertions()) {
            $response->setAssertionSigner($signer);
        }
    }

    private function setResponseIssuer(MockIdentityProvider $mockIdp, Response $response): void
    {
        $response->setIssuer($mockIdp->entityId());
    }

    private function encryptAssertions(MockIdentityProvider $mockIdp, Response $response): void
    {
        $certificate = $mockIdp->getEncryptionCertificate();
        $sharedKey = $mockIdp->getEncryptionSharedKey();
        if ($certificate === null && $sharedKey === null) {
            return;
        }

        $response->encryptAssertions($certificate, $sharedKey);
    }

    private function setConditionsTimes(
        Response $response,
        ?SAMLDateTimeValue $notBefore = null,
        ?SAMLDateTimeValue $notOnOrAfter = null
    ): void {
        $assertions = $response->getAssertions();
        if (!isset($assertions[0]) || !$assertions[0] instanceof Assertion) {
            return;
        }

        $conditions = $assertions[0]->getConditions();
        $response->setAssertion(MessageRebuilder::assertion($assertions[0], [
            'conditions' => new Conditions(
                $notBefore ?? $conditions?->getNotBefore(),
                $notOnOrAfter ?? $conditions?->getNotOnOrAfter(),
                $conditions?->getCondition() ?? [],
                $conditions?->getAudienceRestriction() ?? [],
                $conditions?->getOneTimeUse(),
                $conditions?->getProxyRestriction(),
            ),
        ]));
    }
}
