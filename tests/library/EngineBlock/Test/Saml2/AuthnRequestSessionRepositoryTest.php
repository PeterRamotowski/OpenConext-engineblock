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

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Exception\SessionNotFoundException;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

class EngineBlock_Test_Saml2_AuthnRequestSessionRepositoryTest extends TestCase
{
    private Session $session;
    private EngineBlock_Saml2_AuthnRequestSessionRepository $repo;

    protected function setUp(): void
    {
        $this->session = new Session(new MockArraySessionStorage());
        $requestStack = $this->createMock(RequestStack::class);
        $requestStack->method('getSession')->willReturn($this->session);
        $this->repo = new EngineBlock_Saml2_AuthnRequestSessionRepository($requestStack);
    }

    private function makeRequest(string $id): EngineBlock_Saml2_AuthnRequestAnnotationDecorator
    {
        return EngineBlock_Test_Saml2_MessageFixtures::annotatedAuthnRequest(['id' => $id]);
    }

    public function test_store_saves_request(): void
    {
        $request = $this->makeRequest('_sp-request-A');

        $this->repo->store($request);

        $this->assertSame($request, $this->repo->findRequestById('_sp-request-A'));
    }

    public function test_find_request_by_id_returns_null_for_unknown_id(): void
    {
        $this->assertNull($this->repo->findRequestById('_unknown'));
    }

    public function test_link_stores_request_mapping(): void
    {
        $spRequest  = $this->makeRequest('_sp-request-A');
        $idpRequest = $this->makeRequest('_idp-request-B');

        $this->repo->store($spRequest);
        $this->repo->link($idpRequest, $spRequest);

        $this->assertSame('_sp-request-A', $this->repo->findLinkedRequestId('_idp-request-B'));
    }

    public function test_find_linked_request_id_returns_null_for_unknown_id(): void
    {
        $this->assertNull($this->repo->findLinkedRequestId('_unknown'));
    }

    public function test_find_linked_request_id_returns_null_for_null_input(): void
    {
        $this->assertNull($this->repo->findLinkedRequestId(null));
    }

    public function test_store_and_find_multiple_requests(): void
    {
        $req1 = $this->makeRequest('_req-1');
        $req2 = $this->makeRequest('_req-2');

        $this->repo->store($req1);
        $this->repo->store($req2);

        $this->assertSame($req1, $this->repo->findRequestById('_req-1'));
        $this->assertSame($req2, $this->repo->findRequestById('_req-2'));
    }

    public function test_store_is_noop_when_no_session_available(): void
    {
        $requestStack = $this->createMock(RequestStack::class);
        $requestStack->method('getSession')
            ->willThrowException(new SessionNotFoundException());

        $repo = new EngineBlock_Saml2_AuthnRequestSessionRepository($requestStack);
        $request = $this->makeRequest('_req-A');

        $repo->store($request); // must not throw

        $this->assertNull($this->repo->findRequestById('_req-A'));
    }

    public function test_link_is_noop_when_no_session_available(): void
    {
        $requestStack = $this->createMock(RequestStack::class);
        $requestStack->method('getSession')
            ->willThrowException(new SessionNotFoundException());

        $repo = new EngineBlock_Saml2_AuthnRequestSessionRepository($requestStack);
        $spRequest  = $this->makeRequest('_sp-A');
        $idpRequest = $this->makeRequest('_idp-B');

        $repo->link($idpRequest, $spRequest); // must not throw

        $this->assertNull($this->repo->findLinkedRequestId('_idp-B'));
    }

    public function test_find_request_is_noop_when_no_session_available(): void
    {
        $requestStack = $this->createMock(RequestStack::class);
        $requestStack->method('getSession')
            ->willThrowException(new SessionNotFoundException());

        $repo = new EngineBlock_Saml2_AuthnRequestSessionRepository($requestStack);

        $this->assertNull($repo->findRequestById('_req-A'));
    }

    public function test_find_linked_is_noop_when_no_session_available(): void
    {
        $requestStack = $this->createMock(RequestStack::class);
        $requestStack->method('getSession')
            ->willThrowException(new SessionNotFoundException());

        $repo = new EngineBlock_Saml2_AuthnRequestSessionRepository($requestStack);

        $this->assertNull($repo->findLinkedRequestId('_req-A'));
    }

    public function test_stored_requests_and_links_survive_session_serialization(): void
    {
        $spRequest = $this->makeRequest('_sp-request-A');
        $spRequest->setKeyId('20260101');
        $this->repo->store($spRequest);
        $this->repo->link($this->makeRequest('_idp-request-B'), $spRequest);

        $this->session->replace(unserialize(serialize($this->session->all())));

        $restored = $this->repo->findRequestById('_sp-request-A');
        $this->assertNotSame($spRequest, $restored);
        $this->assertSame('_sp-request-A', $restored->getId());
        $this->assertSame('20260101', $restored->getKeyId());
        $this->assertSame('_sp-request-A', $this->repo->findLinkedRequestId('_idp-request-B'));
    }

    public function test_request_stored_by_another_release_restarts_the_flow(): void
    {
        $class = EngineBlock_Saml2_AuthnRequestAnnotationDecorator::class;
        $legacy = unserialize(sprintf('O:%d:"%s"%s', strlen($class), $class, substr(serialize(['keyId' => null]), 1)));
        $this->session->set('SAMLRequest', ['_old' => $legacy]);

        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);
        $this->repo->findRequestById('_old');
    }

    public function test_request_of_an_unknown_class_restarts_the_flow(): void
    {
        $this->session->set('SAMLRequest', ['_old' => unserialize('O:21:"SAML2_Removed_Message":0:{}')]);

        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);
        $this->repo->findRequestById('_old');
    }
}
