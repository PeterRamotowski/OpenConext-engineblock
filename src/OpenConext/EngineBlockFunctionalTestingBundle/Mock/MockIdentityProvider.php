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

use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\Response;
use ReflectionClass;
use RuntimeException;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\md\AbstractRoleDescriptorType;
use SimpleSAML\SAML2\XML\md\IDPSSODescriptor;
use SimpleSAML\SAML2\XML\md\SingleSignOnService;

/**
 * Configuration (persisted as plain data):
 * - ssoLocation: the SSO location (HTTP-Redirect binding) of the mock IdP
 * - responseXml: the (unsigned) template Response the mock IdP sends
 * - signResponses, signAssertions, useRedirect: booleans
 * - signatureMethod: the XML signature algorithm (RSA-SHA256 by default)
 * - encryptionCert: path to the certificate to encrypt the assertions to (RSA-OAEP)
 * - encryptionSharedKey: shared key to encrypt the assertions with (AES-128-CBC)
 * - statusCodeTop, statusCodeSecond, statusMessage: status overrides
 * - authnContextClassRef: AuthnContextClassRef override, written as is (may be an invalid URI)
 *
 * @SuppressWarnings(PHPMD.TooManyPublicMethods) Allows for better control
 * @SuppressWarnings(PHPMD.ExcessiveClassComplexity)
 */
class MockIdentityProvider extends AbstractMockEntityRole
{
    private $sendAssertions = true;

    private $turnBackTime = false;

    private $fromTheFuture = false;

    private $omitInResponseTo = false;

    public function singleSignOnLocation()
    {
        return $this->config['ssoLocation'];
    }

    protected function buildRoleDescriptor(array $keyDescriptors): AbstractRoleDescriptorType
    {
        return new IDPSSODescriptor(
            singleSignOnService: [
                new SingleSignOnService(
                    SAMLAnyURIValue::fromString(Constants::BINDING_HTTP_REDIRECT),
                    SAMLAnyURIValue::fromString($this->singleSignOnLocation()),
                ),
            ],
            protocolSupportEnumeration: $this->protocolSupportEnumeration(),
            keyDescriptor: $keyDescriptors,
        );
    }

    /**
     * Store the (unsigned) template Response the mock IdP sends.
     */
    public function setResponse(Response $response)
    {
        $this->config['responseXml'] = Saml2Value::toXmlString($response->getSspMessage());

        return $this;
    }

    /**
     * A fresh copy of the template Response.
     *
     * @return Response
     */
    public function getResponse()
    {
        return Response::fromXml($this->config['responseXml']);
    }

    public function setStatusMessage($statusMessage)
    {
        $this->config['statusMessage'] = $statusMessage;
    }

    public function setStatusCode($topLevelStatusCode, $secondLevelStatusCode = '')
    {
        $this->config['statusCodeTop'] = $this->getFullyQualifiedStatusCode($topLevelStatusCode);
        if (!empty($secondLevelStatusCode)) {
            $this->config['statusCodeSecond'] = $this->getFullyQualifiedStatusCode($secondLevelStatusCode);
        }
    }

    private function getFullyQualifiedStatusCode($shortStatusCode)
    {
        $class = new ReflectionClass(Constants::class);
        $constants = $class->getConstants();
        foreach ($constants as $constName => $constValue) {
            if (strpos($constName, 'STATUS_') !== 0 || $constName === 'STATUS_PREFIX') {
                continue;
            }

            if (strpos($constValue, $shortStatusCode) === false) {
                continue;
            }

            return $constValue;
        }

        throw new RuntimeException(sprintf('"%s" is not a valid status code', $shortStatusCode));
    }

    public function getStatusCodeTop()
    {
        return $this->config['statusCodeTop'] ?? Constants::STATUS_SUCCESS;
    }

    public function getStatusCodeSecond()
    {
        return $this->config['statusCodeSecond'] ?? '';
    }

    public function getStatusMessage()
    {
        return $this->config['statusMessage'] ?? '';
    }

    public function useHttpRedirect()
    {
        $this->config['useRedirect'] = true;
        return $this;
    }

    public function mustUseHttpRedirect()
    {
        return !empty($this->config['useRedirect']);
    }

    public function useEncryptionCert($certFilePath)
    {
        $this->config['encryptionCert'] = $certFilePath;
        // an encrypted response must be signed
        $this->useResponseSigning();

        return $this;
    }

    public function useEncryptionSharedKey($sharedKey)
    {
        $this->config['encryptionSharedKey'] = $sharedKey;
        return $this;
    }

    /**
     * The PEM certificate to encrypt the assertions to, if any.
     */
    public function getEncryptionCertificate(): ?string
    {
        if (empty($this->config['encryptionCert'])) {
            return null;
        }

        return $this->readFile($this->config['encryptionCert']);
    }

    /**
     * The shared key to encrypt the assertions with, if any (and no encryption certificate is configured).
     */
    public function getEncryptionSharedKey(): ?string
    {
        if ($this->getEncryptionCertificate() !== null || empty($this->config['encryptionSharedKey'])) {
            return null;
        }

        return $this->config['encryptionSharedKey'];
    }

    public function removeAttribute($forbiddenAttributeName)
    {
        $response = $this->getResponse();

        $newAttributes = [];
        foreach ($response->getAttributes() as $attributeName => $attributeValues) {
            if ($attributeName === $forbiddenAttributeName) {
                continue;
            }

            $newAttributes[$attributeName] = $attributeValues;
        }

        $response->setAttributes($newAttributes);
        $this->setResponse($response);
    }

    public function setAttribute($attributeName, array $attributeValues)
    {
        $response = $this->getResponse();

        $newAttributes = $response->getAttributes();
        $newAttributes[$attributeName] = $attributeValues;

        $response->setAttributes($newAttributes);
        $this->setResponse($response);
    }

    public function setAuthnContextClassRef($authnContextClassRefValue)
    {
        $this->config['authnContextClassRef'] = $authnContextClassRefValue;
    }

    public function getAuthnContextClassRef(): ?string
    {
        return $this->config['authnContextClassRef'] ?? null;
    }

    public function useSignatureMethod(string $signatureMethod)
    {
        $this->config['signatureMethod'] = $signatureMethod;
        return $this;
    }

    public function getSignatureMethod(): string
    {
        return $this->config['signatureMethod'] ?? Constants::SIG_RSA_SHA256;
    }

    public function useResponseSigning()
    {
        $this->config['signResponses'] = true;
        return $this;
    }

    public function mustSignResponses()
    {
        return !empty($this->config['signResponses']);
    }

    public function doNotUseResponseSigning()
    {
        $this->config['signResponses'] = false;
        return $this;
    }

    public function signAssertions()
    {
        $this->config['signAssertions'] = true;
        return $this;
    }

    public function mustSignAssertions()
    {
        return !empty($this->config['signAssertions']);
    }

    public function doNotSendAssertions()
    {
        $this->sendAssertions = false;

        return $this;
    }

    public function shouldTurnBackTheTime()
    {
        return $this->turnBackTime;
    }

    public function turnBackTheTime()
    {
        $this->turnBackTime = true;

        return $this;
    }

    public function isFromTheFuture()
    {
        return $this->fromTheFuture;
    }

    public function fromTheFuture()
    {
        $this->fromTheFuture = true;

        return $this;
    }

    public function omitInResponseTo(): self
    {
        $this->omitInResponseTo = true;

        return $this;
    }

    public function shouldOmitInResponseTo(): bool
    {
        return $this->omitInResponseTo;
    }

    public function shouldNotSendAssertions()
    {
        return $this->sendAssertions === false;
    }
}
