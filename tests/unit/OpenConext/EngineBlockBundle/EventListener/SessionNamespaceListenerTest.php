<?php

/**
 * Copyright 2026 SURFnet B.V.
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

namespace OpenConext\EngineBlockBundle\Tests;

use EngineBlock_Saml2_MessageAnnotationDecorator;
use OpenConext\EngineBlockBundle\EventListener\SessionNamespaceListener;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SessionNamespaceListenerTest extends TestCase
{
    private const COOKIE_NAME = 'engineblock_session_v7';

    protected function tearDown(): void
    {
        unset($_SESSION);
    }

    #[Test]
    public function a_session_written_by_this_release_is_kept(): void
    {
        $_SESSION = [SessionNamespaceListener::SESSION_KEY => $this->expectedNamespace()];
        [$request, $session] = $this->requestWithPreviousSession();
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->never())->method('notice');

        (new SessionNamespaceListener(self::COOKIE_NAME, $logger))->onKernelRequest($this->requestEvent($request));

        $this->assertSame('in-flight', $session->get('flow'));
    }

    #[Test]
    public function a_session_without_this_release_marker_is_invalidated(): void
    {
        $_SESSION = [SessionNamespaceListener::SESSION_KEY => 'main|engineblock-saml2-v4/1'];
        [$request, $session] = $this->requestWithPreviousSession();
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('notice')->with(
            $this->anything(),
            ['session_namespace' => 'main|engineblock-saml2-v4/1', 'expected_namespace' => $this->expectedNamespace()]
        );

        (new SessionNamespaceListener(self::COOKIE_NAME, $logger))->onKernelRequest($this->requestEvent($request));

        $this->assertFalse($session->has('flow'));
    }

    #[Test]
    public function a_request_without_a_previous_session_does_not_start_one(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $request = new Request();
        $request->setSession($session);

        (new SessionNamespaceListener(self::COOKIE_NAME, new NullLogger()))->onKernelRequest($this->requestEvent($request));

        $this->assertFalse($session->isStarted());
    }

    #[Test]
    public function a_symfony_session_marked_on_response_is_kept_on_the_next_request(): void
    {
        $storage = new MockArraySessionStorage();
        $session = new Session($storage);
        $session->set('flow', 'in-flight');
        $request = new Request();
        $request->setSession($session);
        $listener = new SessionNamespaceListener(self::COOKIE_NAME, new NullLogger());

        $listener->onKernelResponse(new ResponseEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            new Response()
        ));
        $session->save();

        $nextRequest = new Request();
        $nextSession = new Session($storage);
        $nextRequest->setSession($nextSession);
        $nextRequest->cookies->set($nextSession->getName(), 'session-id');
        $listener->onKernelRequest($this->requestEvent($nextRequest));

        $this->assertSame('in-flight', $nextSession->get('flow'));
    }

    #[Test]
    #[RunInSeparateProcess]
    public function a_natively_started_session_is_marked_on_response(): void
    {
        ini_set('session.use_cookies', '0');
        ini_set('session.cache_limiter', '');
        session_save_path(sys_get_temp_dir());
        session_start();

        (new SessionNamespaceListener(self::COOKIE_NAME, new NullLogger()))->onKernelResponse(new ResponseEvent(
            $this->createStub(HttpKernelInterface::class),
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            new Response()
        ));

        $this->assertSame($this->expectedNamespace(), $_SESSION[SessionNamespaceListener::SESSION_KEY]);
        session_destroy();
    }

    private function expectedNamespace(): string
    {
        return self::COOKIE_NAME . '|' . EngineBlock_Saml2_MessageAnnotationDecorator::SERIALIZATION_FORMAT;
    }

    /**
     * @return array{Request, Session}
     */
    private function requestWithPreviousSession(): array
    {
        $storage = new MockArraySessionStorage();
        $storage->setSessionData(['_sf2_attributes' => ['flow' => 'in-flight']]);
        $session = new Session($storage);

        $request = new Request();
        $request->setSession($session);
        $request->cookies->set($session->getName(), 'session-id');

        return [$request, $session];
    }

    private function requestEvent(Request $request): RequestEvent
    {
        return new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST
        );
    }
}
