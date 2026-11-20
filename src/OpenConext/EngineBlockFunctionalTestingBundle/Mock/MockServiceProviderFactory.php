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
use Symfony\Component\Routing\RouterInterface;

/**
 * Class MockServiceProviderFactory
 * @package OpenConext\EngineBlockFunctionalTestingBundle\Service
 */
class MockServiceProviderFactory extends AbstractMockEntityFactory
{
    protected $router;

    /**
     * @param RouterInterface $router
     */
    public function __construct(RouterInterface $router)
    {
        $this->router = $router;
    }

    public function createNew($spName)
    {
        $mockSp = new MockServiceProvider($spName, $this->generateDefaultEntityConfiguration($spName));

        $mockSp->setAuthnRequest(AuthnRequest::create($mockSp->entityId()));

        return $mockSp;
    }

    protected function generateDefaultEntityConfiguration($spName)
    {
        return [
            'entityId' => $this->router->generate(
                'functional_testing_sp_metadata',
                ['spName' => $spName],
                RouterInterface::ABSOLUTE_URL
            ),
            'acsLocation' => $this->router->generate(
                'functional_testing_sp_acs',
                ['spName' => $spName],
                RouterInterface::ABSOLUTE_URL
            ),
            'loginRedirectUrl' => $this->router->generate(
                'functional_testing_sp_login_redirect',
                ['spName' => $spName],
                RouterInterface::ABSOLUTE_URL
            ),
            'loginPostUrl' => $this->router->generate(
                'functional_testing_sp_login_post',
                ['spName' => $spName],
                RouterInterface::ABSOLUTE_URL
            ),
        ] + $this->generateDefaultSigningKeyPair();
    }
}
