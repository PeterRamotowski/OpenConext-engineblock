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

use OpenConext\EngineBlock\Metadata\Entity\IdentityProvider;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\XMLSchema\Type\IDValue;

class EngineBlock_Saml2_AuthnRequestFactory
{
    public static function createFromRequest(
        EngineBlock_Saml2_AuthnRequestAnnotationDecorator $originalRequest,
        IdentityProvider $idpMetadata,
        EngineBlock_Corto_ProxyServer $server,
        $issuerServiceName = 'spMetadataService',
        $acsServiceName = 'assertionConsumerService'
    ) {
        $nameIdPolicy = array('AllowCreate' => true);
        /**
         * Name policy is not required, so it is only set if configured, SAML 2.0 spec
         * says only following values are allowed:
         *  - urn:oasis:names:tc:SAML:2.0:nameid-format:transient
         *  - urn:oasis:names:tc:SAML:2.0:nameid-format:persistent.
         *
         * Note: Some IDP's like those using ADFS2 do not understand those, for these cases the format can be 'configured as empty
         * or set to an older version.
         */
        if (!empty($idpMetadata->nameIdFormat)) {
            $nameIdPolicy['Format'] = $idpMetadata->nameIdFormat;
        }

        $destination = isset($idpMetadata->singleSignOnServices[0]) ? $idpMetadata->singleSignOnServices[0]->location : null;
        $request = new EngineBlock_Saml2_AuthnRequestAnnotationDecorator(new AuthnRequest(
            id: IDValue::fromString($server->getNewId(\OpenConext\EngineBlock\Saml2\IdGenerator::ID_USAGE_SAML2_REQUEST)),
            issueInstant: Saml2Value::dateTime(time()),
            assertionConsumerServiceURL: SAMLAnyURIValue::fromString($server->getUrl($acsServiceName)),
            protocolBinding: SAMLAnyURIValue::fromString(Constants::BINDING_HTTP_POST),
            issuer: Saml2Value::issuer($server->getUrl($issuerServiceName)),
            destination: $destination === null || $destination === '' ? null : SAMLAnyURIValue::fromString($destination),
        ));
        $request->setForceAuthn($originalRequest->getForceAuthn());
        $request->setIsPassive($originalRequest->getIsPassive());
        $request->setNameIdPolicy($nameIdPolicy);

        if (empty($idpMetadata->getCoins()->disableScoping())) {
            // Copy over the Idps that are allowed to answer this request.
            $request->setIDPList($originalRequest->getIDPList());

            // Proxy Count
            $request->setProxyCount(
                $originalRequest->getProxyCount() ?
                    $originalRequest->getProxyCount() :
                    (int) $server->getConfig('max_proxies', 10)
            );

            // Add the SP to the requesterIds
            $requesterIds = $originalRequest->getRequesterID();
            $requesterIds[] = ($originalRequest->getIssuerValue() ?? '');

            // Add the SP as the requester
            $request->setRequesterID($requesterIds);
        }

        // Use the default binding even if more exist
        $request->setDeliverByBinding(isset($idpMetadata->singleSignOnServices[0]) ? $idpMetadata->singleSignOnServices[0]->binding : null);

        return $request;
    }

    /**
     * @param EngineBlock_Http_Request $httpRequest
     * @return AuthnRequest
     */
    public function createFromHttpRequest(EngineBlock_Http_Request $httpRequest)
    {
        $parameter = $this->getParameterFromHttpRequest($httpRequest);
        $requestXml = $this->decodeParameter($parameter);

        $serializer = new EngineBlock_Saml2_MessageSerializer();
        return $serializer->deserialize($requestXml, AuthnRequest::class);
    }

    /**
     * @param EngineBlock_Http_Request $httpRequest
     * @return string
     * @throws Exception
     */
    private function getParameterFromHttpRequest(EngineBlock_Http_Request $httpRequest)
    {
        $parameter = $httpRequest->getQueryParameter('SAMLRequest');
        if (empty($parameter)) {
            throw new Exception('No SAMLRequest parameter');
        }

        return $parameter;
    }

    /**
     * @param string $parameter
     * @return string
     */
    private function decodeParameter($parameter)
    {
        return gzinflate(base64_decode($parameter));
    }
}
