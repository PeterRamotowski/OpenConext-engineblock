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

namespace OpenConext\EngineBlockBundle\EventListener;

use EngineBlock_Saml2_MessageAnnotationDecorator;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * D7 session cutover: a session is only used by the release (storage namespace) that wrote it.
 *
 * Every session written by this release carries a namespace marker. A session presented without the expected
 * marker (a reused cookie name, a rollback, or a release with another serialization format) is invalidated before
 * EngineBlock uses any authentication state from it.
 *
 * This is an additional check only: PHP has already deserialized the session data when the marker is read, so it
 * does not prevent cross-version deserialization. That requires separate or purged session storage, plus a fresh
 * session cookie name for a cutover or roll forward (docs/session_cutover.md).
 */
final class SessionNamespaceListener
{
    public const SESSION_KEY = 'engineblock.session_namespace';

    private string $namespace;

    public function __construct(string $sessionCookieName, private readonly LoggerInterface $logger)
    {
        $this->namespace = $sessionCookieName . '|' . EngineBlock_Saml2_MessageAnnotationDecorator::SERIALIZATION_FORMAT;
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        if (!$request->hasPreviousSession()) {
            return;
        }

        $session = $request->getSession();
        if (!$session->isStarted() && session_status() !== PHP_SESSION_ACTIVE) {
            $session->start();
        }

        $marker = $_SESSION[self::SESSION_KEY] ?? $session->get(self::SESSION_KEY);
        if ($marker === $this->namespace) {
            return;
        }

        $this->logger->notice(
            'Discarding session state that was not written by this release',
            ['session_namespace' => is_string($marker) ? $marker : null, 'expected_namespace' => $this->namespace]
        );
        $session->invalidate();
    }

    /**
     * With native storage the marker is a top-level $_SESSION key, like the Corto flow state: Corto starts the session
     * natively (EngineBlock_Corto_ProxyServer::startSession()), which Symfony's Session::isStarted() does not report.
     * Other storages (e.g. the mock storage in tests) keep it as a session attribute.
     */
    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            if (($_SESSION[self::SESSION_KEY] ?? null) !== $this->namespace) {
                $_SESSION[self::SESSION_KEY] = $this->namespace;
            }
            return;
        }

        $request = $event->getRequest();
        if (!$request->hasSession()) {
            return;
        }

        $session = $request->getSession();
        if ($session->isStarted() && $session->get(self::SESSION_KEY) !== $this->namespace) {
            $session->set(self::SESSION_KEY, $this->namespace);
        }
    }
}
