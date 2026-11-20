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

declare(strict_types=1);

namespace OpenConext\EngineBlockBundle\Tests;

use App\Kernel;
use EngineBlock_Saml2_MessageAnnotationDecorator;
use OpenConext\EngineBlockBundle\EventListener\SessionNamespaceListener;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class WayfControllerTest extends TestCase
{
    #[Test]
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function removing_all_cookies_destroys_the_active_session_and_expires_its_cookie(): void
    {
        // The ci environment uses native storage and enables remember-choice.
        $kernel = new Kernel('ci', true);
        $kernel->boot();
        $cookieName = $kernel->getContainer()->getParameter('session_cookie_name');

        session_save_path(sys_get_temp_dir());
        session_name($cookieName);
        $sessionId = bin2hex(random_bytes(16));
        $sessionFile = session_save_path() . '/sess_' . $sessionId;
        session_id($sessionId);

        try {
            session_start();
            $_SESSION[SessionNamespaceListener::SESSION_KEY] =
                $cookieName . '|' . EngineBlock_Saml2_MessageAnnotationDecorator::SERIALIZATION_FORMAT;
            $_SESSION['wayf_test_flow'] = 'in-flight';
            session_write_close();
            self::assertFileExists($sessionFile);

            $_COOKIE[$cookieName] = $sessionId;
            $request = Request::create(
                'https://engine.dev.openconext.local/authentication/idp/remove-cookies',
                'POST',
                ['remove_all' => '1'],
                [$cookieName => $sessionId]
            );

            $response = $kernel->handle($request);
            $sessionCookies = array_values(array_filter(
                $response->headers->getCookies(),
                static fn (Cookie $cookie): bool => $cookie->getName() === $cookieName
            ));

            self::assertSame(Response::HTTP_OK, $response->getStatusCode());
            self::assertFileDoesNotExist($sessionFile);
            self::assertCount(1, $sessionCookies);
            self::assertTrue($sessionCookies[0]->isCleared());
        } finally {
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_abort();
            }
            if (is_file($sessionFile)) {
                unlink($sessionFile);
            }
            $kernel->shutdown();
        }
    }
}
