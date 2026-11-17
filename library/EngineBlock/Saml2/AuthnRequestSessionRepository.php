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

use Symfony\Component\HttpFoundation\Exception\SessionNotFoundException;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Session storage for Authentication Requests. Store AuthnRequests and link requests together.
 *
 * Uses the Symfony session bag under two keys:
 *   'SAMLRequest'      — map of requestId => AuthnRequestAnnotationDecorator
 *   'SAMLRequestLinks' — map of idpRequestId => spRequestId
 *
 * All methods are safe no-ops when no session is available (unit tests, CLI).
 */
class EngineBlock_Saml2_AuthnRequestSessionRepository
{
    private const string SESSION_KEY_REQUESTS = 'SAMLRequest';
    private const string SESSION_KEY_LINKS    = 'SAMLRequestLinks';

    private const string SESSION_KEY_PENDING = 'SAMLRequestPending';

    public const int REQUEST_LIFETIME_SECONDS = 300;

    /**
     * @var RequestStack
     */
    private $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
    }

    /**
     * @param string $requestId
     * @return EngineBlock_Saml2_AuthnRequestAnnotationDecorator|null
     * @throws EngineBlock_Corto_Module_Services_SessionLostException when the stored state is from another release
     * @throws EngineBlock_Corto_Module_Bindings_VerificationException when the stored message cannot be decoded
     */
    public function findRequestById($requestId)
    {
        try {
            $session = $this->requestStack->getSession();
        } catch (SessionNotFoundException $e) {
            return null;
        }

        $request = $session->get(self::SESSION_KEY_REQUESTS, [])[$requestId] ?? null;
        if ($request === null) {
            return null;
        }

        // State that was not written by this release is never trusted; the flow restarts via session-lost feedback.
        if (!$request instanceof EngineBlock_Saml2_AuthnRequestAnnotationDecorator) {
            throw new EngineBlock_Corto_Module_Services_SessionLostException(
                sprintf('Stored request "%s" is not readable by this release', $requestId)
            );
        }
        $request->assertRestored();

        return $request;
    }

    /**
     * @param string|null $requestId
     * @return string|null
     */
    public function findLinkedRequestId($requestId)
    {
        if (!$requestId) {
            return null;
        }

        try {
            $session = $this->requestStack->getSession();
        } catch (SessionNotFoundException $e) {
            return null;
        }

        return $session->get(self::SESSION_KEY_LINKS, [])[$requestId] ?? null;
    }

    /**
     * @param EngineBlock_Saml2_AuthnRequestAnnotationDecorator $spRequest
     * @return $this
     */
    public function store(EngineBlock_Saml2_AuthnRequestAnnotationDecorator $spRequest)
    {
        try {
            $session = $this->requestStack->getSession();
        } catch (SessionNotFoundException $e) {
            return $this;
        }

        $requests = $session->get(self::SESSION_KEY_REQUESTS, []);
        $requests[$spRequest->getId()] = $spRequest;
        $session->set(self::SESSION_KEY_REQUESTS, $requests);

        return $this;
    }

    /**
     * @param EngineBlock_Saml2_AuthnRequestAnnotationDecorator $fromRequest
     * @param EngineBlock_Saml2_AuthnRequestAnnotationDecorator $toRequest
     * @return $this
     */
    public function link(
        EngineBlock_Saml2_AuthnRequestAnnotationDecorator $fromRequest,
        EngineBlock_Saml2_AuthnRequestAnnotationDecorator $toRequest,
        ?string $identityProvider = null
    ) {
        try {
            $session = $this->requestStack->getSession();
        } catch (SessionNotFoundException $e) {
            return $this;
        }

        $links = $session->get(self::SESSION_KEY_LINKS, []);
        $links[$fromRequest->getId()] = $toRequest->getId();
        $session->set(self::SESSION_KEY_LINKS, $links);

        $pending = $session->get(self::SESSION_KEY_PENDING, []);
        $pending[$fromRequest->getId()] = [
            'identityProvider' => $identityProvider,
            'assertionConsumerUrl' => $fromRequest->getAssertionConsumerServiceURL(),
            'issuedAt' => $fromRequest->getIssueInstant(),
        ];
        $session->set(self::SESSION_KEY_PENDING, $pending);

        return $this;
    }

    /**
     * Consume a live request once, while keeping its SP link for subsequent consent/Stepup processing.
     */
    public function consumePendingRequest(string $requestId, string $identityProvider, string $destination, int $now): void
    {
        try {
            $session = $this->requestStack->getSession();
        } catch (SessionNotFoundException $exception) {
            throw new EngineBlock_Corto_Module_Services_SessionLostException('Session lost', 0, $exception);
        }

        $pending = $session->get(self::SESSION_KEY_PENDING, []);
        $context = $pending[$requestId] ?? null;
        if (!is_array($context) || !is_int($context['issuedAt'] ?? null)
            || $now - $context['issuedAt'] >= self::REQUEST_LIFETIME_SECONDS
            || $context['issuedAt'] > $now + 60
        ) {
            throw new EngineBlock_Corto_Module_Services_SessionLostException(
                'The authentication request is no longer pending or has expired'
            );
        }

        if (($context['identityProvider'] ?? null) !== $identityProvider
            || ($context['assertionConsumerUrl'] ?? null) !== $destination
        ) {
            throw new EngineBlock_Corto_Module_Bindings_VerificationException(
                'The Response does not match the identity provider and ACS of the pending request'
            );
        }

        unset($pending[$requestId]);
        $session->set(self::SESSION_KEY_PENDING, $pending);
    }
}
