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

use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\AuthnRequest;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\md\AbstractRoleDescriptorType;
use SimpleSAML\SAML2\XML\md\AssertionConsumerService;
use SimpleSAML\SAML2\XML\md\SPSSODescriptor;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use SimpleSAML\XMLSchema\Type\UnsignedShortValue;

/**
 * Configuration (persisted as plain data):
 * - acsLocation: the ACS location (HTTP-POST binding) of the mock SP
 * - loginRedirectUrl, loginPostUrl: the URLs that make the mock SP start a login
 * - transparentIdp: entityId of the IdP to use transparently
 * - unsolicited, authnRequestsSigned, usePost, trustedProxy, malformed: booleans
 * - authnContextClassRef: AuthnContextClassRef setting
 * The AuthnRequest the mock SP sends is persisted as XML (see AuthnRequest::__serialize()).
 *
 * @package OpenConext\EngineBlockFunctionalTestingBundle\Mock
 * @SuppressWarnings("PMD")
 */
class MockServiceProvider extends AbstractMockEntityRole
{
    private ?AuthnRequest $authnRequest = null;

    public function loginUrlRedirect()
    {
        return $this->config['loginRedirectUrl'];
    }

    public function loginUrlPost()
    {
        return $this->config['loginPostUrl'];
    }

    public function assertionConsumerServiceLocation()
    {
        return $this->config['acsLocation'];
    }

    protected function buildRoleDescriptor(array $keyDescriptors): AbstractRoleDescriptorType
    {
        return new SPSSODescriptor(
            assertionConsumerService: [
                new AssertionConsumerService(
                    UnsignedShortValue::fromString('0'),
                    SAMLAnyURIValue::fromString(Constants::BINDING_HTTP_POST),
                    SAMLAnyURIValue::fromString($this->assertionConsumerServiceLocation()),
                ),
            ],
            protocolSupportEnumeration: $this->protocolSupportEnumeration(),
            authnRequestsSigned: $this->mustSignAuthnRequests() ? BooleanValue::fromBoolean(true) : null,
            keyDescriptors: $keyDescriptors,
        );
    }

    /**
     * @return AuthnRequest
     */
    public function getAuthnRequest()
    {
        return $this->authnRequest;
    }

    public function setAuthnRequest(AuthnRequest $authnRequest)
    {
        $this->authnRequest = $authnRequest;
    }

    public function useIdpTransparently($entityId)
    {
        $this->config['transparentIdp'] = $entityId;
    }

    public function getTransparentIdp()
    {
        return $this->config['transparentIdp'] ?? '';
    }

    public function mustUseUnsolicited()
    {
        return !empty($this->config['unsolicited']);
    }

    public function signAuthnRequests()
    {
        $this->config['authnRequestsSigned'] = true;
        return $this;
    }

    public function mustSignAuthnRequests()
    {
        return !empty($this->config['authnRequestsSigned']);
    }

    public function useHttpPost()
    {
        $this->config['usePost'] = true;
    }

    public function mustUsePost()
    {
        return !empty($this->config['usePost']);
    }

    public function useHttpRedirect()
    {
        $this->config['usePost'] = false;
    }

    public function isTrustedProxy()
    {
        return !empty($this->config['trustedProxy']);
    }

    public function setAuthnRequestProxyCountTo($proxyCount)
    {
        $this->authnRequest->setProxyCount($proxyCount === null ? null : (int) $proxyCount);
    }

    public function setRequestedProtocolBinding(string $binding)
    {
        $this->authnRequest->setProtocolBinding($binding);
    }

    public function setAuthnRequestToPassive()
    {
        $this->authnRequest->setIsPassive(true);
    }

    /**
     * @param string $idpEntityId
     */
    public function addIdpToScope($idpEntityId)
    {
        $scope = $this->getScoping();
        $scope[] = $idpEntityId;

        $this->authnRequest->setIDPList($scope);
    }

    public function sendMalformedAuthNRequest()
    {
        $this->config['malformed'] = true;
    }

    public function mustSendMalformedAuthnRequest(): bool
    {
        return !empty($this->config['malformed']);
    }

    /**
     * @return array
     */
    public function getScoping()
    {
        return $this->authnRequest->getIDPList();
    }

    public function setAuthnContextClassRef($classRef)
    {
        $this->config['authnContextClassRef'] = $classRef;
    }

    public function getAuthnContextClassRef(): ?string
    {
        return $this->config['authnContextClassRef'] ?? null;
    }
}
