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

use Exception;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use OpenConext\EngineBlockFunctionalTestingBundle\Mock\EntityRegistry;
use OpenConext\EngineBlockFunctionalTestingBundle\Mock\MockServiceProvider;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\AuthnRequestFactory;
use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\HttpBinding;
use OpenConext\EngineBlockFunctionalTestingBundle\Service\EngineBlock;
use RuntimeException;
use SimpleSAML\SAML2\XML\samlp\Response as SAMLResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * @package OpenConext\EngineBlockFunctionalTestingBundle\Controllers
 * @SuppressWarnings("PMD")
 */
class ServiceProviderController extends AbstractController
{
    /**
     * @var EntityRegistry
     */
    private $mockSpRegistry;

    /**
     * @var EngineBlock
     */
    private $engineBlock;

    public function __construct(EntityRegistry $spRegistry, EngineBlock $engineBlock)
    {
        $this->mockSpRegistry = $spRegistry;
        $this->engineBlock = $engineBlock;
    }

    /**
     * @param $spName
     * @return RedirectResponse
     * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     */
    public function triggerLoginRedirectAction(Request $request, $spName)
    {
        if (!$this->mockSpRegistry->has($spName)) {
            throw new BadRequestHttpException(sprintf('No SP found for "%s"', $spName));
        }

        /** @var MockServiceProvider $sp */
        $sp = $this->mockSpRegistry->get($spName);

        $factory = new AuthnRequestFactory();
        $authnRequest = $factory->createForRequestFromTo(
            $sp,
            $this->engineBlock,
            $request->getSchemeAndHttpHost()
        );

        $url = HttpBinding::redirectUrl(
            $authnRequest->getDestination(),
            HttpBinding::PARAMETER_REQUEST,
            $authnRequest->toXml(),
            $authnRequest->getRelayState(),
            $authnRequest->getSigner()
        );

        if ($sp->mustSendMalformedAuthnRequest()) {
            $url = str_replace('SAMLRequest', 'AuthNRequest', $url);
        }

        return new RedirectResponse($url);
    }

    /**
     * @param $spName
     * @return Response
     * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     */
    public function triggerLoginPostAction(Request $request, $spName)
    {
        if (!$this->mockSpRegistry->has($spName)) {
            throw new BadRequestHttpException(sprintf('No SP found for "%s"', $spName));
        }

        $factory = new AuthnRequestFactory();
        /** @var MockServiceProvider $sp */
        $sp = $this->mockSpRegistry->get($spName);
        $authnRequest = $factory->createForRequestFromTo(
            $sp,
            $this->engineBlock,
            $request->getSchemeAndHttpHost()
        );

        $data = [HttpBinding::PARAMETER_REQUEST => base64_encode($authnRequest->toSignedXml())];
        if ($authnRequest->getRelayState() !== null) {
            $data[HttpBinding::PARAMETER_RELAY_STATE] = $authnRequest->getRelayState();
        }
        $response = HttpBinding::postForm($authnRequest->getDestination(), $data);

        if ($sp->mustSendMalformedAuthnRequest()) {
            $body = $response->getContent();
            $response->setContent(str_replace('SAMLRequest', 'AuthNRequest', $body));
        }

        return $response;
    }

    /**
     * @param Request $request
     * @return Response
     * @throws \RuntimeException
     */
    public function assertionConsumerAction(Request $request)
    {
        try {
            $message = HttpBinding::receive($request);
            $element = Saml2Value::documentElement($message['xml']);
        } catch (Exception $e) {
            throw new RuntimeException('Unable to retrieve SAML message?', 1, $e);
        }

        if ($element->localName !== 'Response') {
            throw new RuntimeException(sprintf('Unrecognized message type received: "%s"', $element->localName));
        }
        SAMLResponse::fromXML($element);

        $xml = $message['xml'];

        return new Response(
            HttpBinding::formatXml($xml),
            200,
            ['Content-Type' => 'application/xml']
        );
    }

    /**
     * @param $spName
     * @return Response
     */
    public function metadataAction($spName)
    {
        /** @var MockServiceProvider $mockSp */
        $mockSp = $this->mockSpRegistry->get($spName);

        return new Response(
            Saml2Value::toXmlString($mockSp->getEntityDescriptor()),
            200,
            ['Content-Type' => 'application/xml']
        );
    }
}
