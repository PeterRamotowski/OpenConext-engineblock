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

namespace OpenConext\EngineBlockFunctionalTestingBundle\Controllers;

use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use OpenConext\EngineBlockFunctionalTestingBundle\Mock\EntityRegistry;
use OpenConext\EngineBlockFunctionalTestingBundle\Mock\MockIdentityProvider;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\HttpBinding;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\ResponseFactory;
use RuntimeException;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects) just does a lot of manual lifting :(
 */
class IdentityProviderController extends AbstractController
{
    /**
     * @var EntityRegistry
     */
    private $mockIdpRegistry;
    /**
     * @var ResponseFactory
     */
    private $responseFactory;

    public function __construct(EntityRegistry $mockIdpRegistry, ResponseFactory $responseFactory)
    {
        $this->mockIdpRegistry = $mockIdpRegistry;
        $this->responseFactory = $responseFactory;
    }

    /**
     * @param $idpName
     * @return Response
     */
    public function metadataAction($idpName)
    {
        $entityDescriptor = $this->mockIdpRegistry->get($idpName)->getEntityDescriptor();

        return new Response(
            Saml2Value::toXmlString($entityDescriptor),
            200,
            ['Content-Type' => 'application/xml']
        );
    }

    /**
     * @param Request $request
     * @param $idpName
     * @return Response
     * @throws RuntimeException
     */
    public function singleSignOnAction(Request $request, $idpName)
    {
        $message = HttpBinding::receive($request);
        if ($message['parameter'] !== HttpBinding::PARAMETER_REQUEST) {
            throw new RuntimeException(sprintf('Unknown message type: "%s"', $message['parameter']));
        }

        $element = Saml2Value::documentElement($message['xml']);
        if ($element->localName !== 'AuthnRequest') {
            throw new RuntimeException(sprintf('Unknown message type: "%s"', $element->localName));
        }
        $authnRequest = AuthnRequest::fromXML($element);

        /** @var MockIdentityProvider $mockIdp */
        $mockIdp = $this->mockIdpRegistry->get($idpName);

        $response = $this->responseFactory->createForEntityWithRequest($mockIdp, $authnRequest);

        $destination = ($authnRequest->getAssertionConsumerServiceURL() ?
                $authnRequest->getAssertionConsumerServiceURL()->getValue() :
                $response->getDestination());

        /* set the destination element of the response to the ACS URL */
        $response->setDestination($destination);

        if ($mockIdp->mustUseHttpRedirect()) {
            // Like saml2 4.x: the (unsigned) Response is sent with a query signature when responses must be signed
            $url = HttpBinding::redirectUrl(
                $destination,
                HttpBinding::PARAMETER_RESPONSE,
                $response->toXml(false),
                null,
                $response->getResponseSigner()
            );
            return new RedirectResponse($url);
        }

        return HttpBinding::postForm(
            $destination,
            [
                'authnRequestXml' => htmlentities($message['xml']),
                'SAMLResponse' => base64_encode($response->toXml()),
            ]
        );
    }
}
