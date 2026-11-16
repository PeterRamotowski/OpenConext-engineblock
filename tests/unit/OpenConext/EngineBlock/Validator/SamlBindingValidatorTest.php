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

namespace OpenConext\EngineBlock\Validator;

use OpenConext\EngineBlock\Exception\InvalidBindingException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

class SamlBindingValidatorTest extends TestCase
{
    /**
     * @var SamlBindingValidator
     */
    private $validator;

    public function setUp(): void
    {
        $this->validator = new SamlBindingValidator();
    }

    public function test_happy_flow_get()
    {
        $request = Request::create('/sso', Request::METHOD_GET, ['SAMLRequest' => 'loremipsum']);

        $this->assertTrue($this->validator->isValid($request));
    }

    public function test_happy_flow_post()
    {
        $request = Request::create('/sso', Request::METHOD_POST, ['SAMLResponse' => 'loremipsum']);

        $this->assertTrue($this->validator->isValid($request));
    }

    public function test_query_parameters_do_not_make_a_post_binding()
    {
        $this->expectException(InvalidBindingException::class);
        $this->expectExceptionMessage('No SAMLRequest or SAMLResponse parameter was found in the HTTP "POST" request parameters');

        $request = Request::create('/sso?SAMLRequest=loremipsum', Request::METHOD_POST);

        $this->validator->isValid($request);
    }

    public function test_post_binding_is_not_supported()
    {
        $this->expectException(InvalidBindingException::class);
        $this->expectExceptionMessage('No SAMLRequest or SAMLResponse parameter was found in the HTTP "PATCH" request parameters');

        $request = Request::create('/sso', Request::METHOD_PATCH, ['SAMLRequest' => 'loremipsum']);

        $this->validator->isValid($request);
    }

    public function test_used_invalid_binding()
    {
        $this->expectException(InvalidBindingException::class);
        $this->expectExceptionMessage('No SAMLRequest or SAMLResponse parameter was found in the HTTP');

        // Even though we are handling a AuthNRequest, the binding is based on a get parameter named SAMLRequest
        $request = Request::create('/sso', Request::METHOD_GET, ['AuhtnRequest' => 'loremipsum']);

        $this->validator->isValid($request);
    }

    public function test_used_unsupported_binding()
    {
        $this->expectException(InvalidBindingException::class);
        $this->expectExceptionMessage(
            'The binding type "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" is not supported on this endpoint'
        );

        // EB does not support artifact binding
        $request = Request::create('/sso', Request::METHOD_GET, ['SAMLart' => 'loremipsum']);

        $this->validator->isValid($request);
    }

    public function test_soap_binding_is_not_supported()
    {
        $this->expectException(InvalidBindingException::class);
        $this->expectExceptionMessage(
            'The binding type "urn:oasis:names:tc:SAML:2.0:bindings:SOAP" is not supported on this endpoint'
        );

        $request = Request::create('/sso', Request::METHOD_POST, [], [], [], ['CONTENT_TYPE' => 'text/xml; charset=utf-8']);

        $this->validator->isValid($request);
    }
}
