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

namespace OpenConext\EngineBlock\Service;

use EngineBlock_Corto_Module_Services_SessionLostException;
use EngineBlock_Saml2_MessageAnnotationDecorator;
use EngineBlock_Saml2_ResponseAnnotationDecorator;
use EngineBlock_Test_Saml2_MessageFixtures;
use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use OpenConext\EngineBlock\Metadata\Entity\AbstractRole;
use OpenConext\EngineBlock\Service\Dto\ProcessingStateStep;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

class ProcessingStateHelperTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private Session $session;
    private ProcessingStateHelper $helper;

    protected function setUp(): void
    {
        $this->session = new Session(new MockArraySessionStorage());

        $request = new Request();
        $request->setSession($this->session);

        $requestStack = new RequestStack([$request]);

        $this->helper = new ProcessingStateHelper($requestStack);
    }

    #[Test]
    public function it_stores_and_retrieves_a_processing_step(): void
    {
        $role = m::mock(AbstractRole::class);
        $response = EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse();

        $step = $this->helper->addStep('req-1', ProcessingStateHelperInterface::STEP_CONSENT, $role, $response);

        self::assertInstanceOf(ProcessingStateStep::class, $step);
        self::assertSame($step, $this->helper->getStepByRequestId('req-1', ProcessingStateHelperInterface::STEP_CONSENT));
    }

    #[Test]
    public function it_throws_when_step_not_found(): void
    {
        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);

        $this->helper->getStepByRequestId('nonexistent', ProcessingStateHelperInterface::STEP_CONSENT);
    }

    #[Test]
    public function it_clears_a_step_by_request_id(): void
    {
        $role = m::mock(AbstractRole::class);
        $response = m::mock(EngineBlock_Saml2_ResponseAnnotationDecorator::class);

        $this->helper->addStep('req-1', ProcessingStateHelperInterface::STEP_CONSENT, $role, $response);
        $this->helper->clearStepByRequestId('req-1');

        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);
        $this->helper->getStepByRequestId('req-1', ProcessingStateHelperInterface::STEP_CONSENT);
    }

    #[Test]
    public function it_treats_a_step_from_another_serialization_format_as_session_lost(): void
    {
        $role = m::mock(AbstractRole::class);
        $current = serialize(EngineBlock_Test_Saml2_MessageFixtures::annotatedResponse());
        $foreignFormat = str_replace(
            EngineBlock_Saml2_MessageAnnotationDecorator::SERIALIZATION_FORMAT,
            'engineblock-saml2-v4/1',
            $current
        );
        self::assertNotSame($current, $foreignFormat);
        $response = unserialize($foreignFormat);
        self::assertInstanceOf(EngineBlock_Saml2_ResponseAnnotationDecorator::class, $response);

        $this->helper->addStep('req-1', ProcessingStateHelperInterface::STEP_CONSENT, $role, $response);

        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);
        $this->helper->getStepByRequestId('req-1', ProcessingStateHelperInterface::STEP_CONSENT);
    }

    #[Test]
    public function it_treats_an_unreadable_step_as_session_lost(): void
    {
        $this->session->set(ProcessingStateHelper::SESSION_KEY, [
            'req-1' => [ProcessingStateHelperInterface::STEP_CONSENT => unserialize('O:23:"SAML2_Removed_StateStep":0:{}')],
        ]);

        $this->expectException(EngineBlock_Corto_Module_Services_SessionLostException::class);
        $this->helper->getStepByRequestId('req-1', ProcessingStateHelperInterface::STEP_CONSENT);
    }
}
