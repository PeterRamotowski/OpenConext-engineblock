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

use OpenConext\EngineBlockFunctionalTestingBundle\Mock\MockServiceProvider;
use OpenConext\EngineBlockFunctionalTestingBundle\Service\EngineBlock;

/**
 * Class AuthnRequestFactory
 * @package OpenConext\EngineBlockFunctionalTestingBundle\Saml2
 */
class AuthnRequestFactory
{
    /**
     * @param MockServiceProvider $mockSp
     * @param EngineBlock $engineBlock
     * @param string|null $baseUrl Scheme and host to resolve the (relative) EngineBlock locations against
     * @return AuthnRequest
     * @throws \Exception
     */
    public function createForRequestFromTo(MockServiceProvider $mockSp, EngineBlock $engineBlock, ?string $baseUrl = null)
    {
        // Work on a copy: the signer must not end up in the (persisted) mock SP
        $request = clone $mockSp->getAuthnRequest();

        // Set / override the Destination
        $transparentIdp = $mockSp->getTransparentIdp();
        if (!empty($transparentIdp)) {
            $destination = $engineBlock->transparentSsoLocation($transparentIdp);
        } else {
            $destination = $engineBlock->singleSignOnLocation();
        }
        // SAML 2 requires an absolute Destination URI; the legacy library sent the relative path and relied on
        // the browser resolving the redirect against the current host.
        if ($baseUrl !== null && str_starts_with($destination, '/')) {
            $destination = rtrim($baseUrl, '/') . $destination;
        }
        $request->setDestination($destination);

        if ($mockSp->mustSignAuthnRequests()) {
            $request->setSigner(XmlSecurity::signer($mockSp->getPrivateKeyPem()));
        }

        return $request;
    }
}
