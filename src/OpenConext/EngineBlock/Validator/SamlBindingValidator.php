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
use Symfony\Component\HttpFoundation\Request;

/**
 * The SamlBindingValidator verifies valid saml binding
 *
 * Valid requests method / binding combinations for SSO are:
 *
 *  | SAML Binding     | Request method | Parameter name              |
 *  | ---------------- | -------------- | --------------------------- |
 *  | HttpRedirect     | GET            | SAMLRequest,SAMLResponse    |
 *  | HTTPPost         | POST           | SAMLRequest,SAMLResponse    |
 */
class SamlBindingValidator implements RequestValidator
{
    private const BINDING_HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';
    private const BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP';

    public function isValid(Request $request)
    {
        $parameters = match ($request->getMethod()) {
            Request::METHOD_GET => $request->query,
            Request::METHOD_POST => $request->request,
            default => null,
        };

        if ($parameters !== null && ($parameters->has('SAMLRequest') || $parameters->has('SAMLResponse'))) {
            return true;
        }

        $unsupportedBinding = null;
        if ($parameters !== null && $parameters->has('SAMLart')) {
            $unsupportedBinding = self::BINDING_HTTP_ARTIFACT;
        } elseif ($request->isMethod(Request::METHOD_POST) && $this->isSoapContentType($request)) {
            $unsupportedBinding = self::BINDING_SOAP;
        }

        if ($unsupportedBinding !== null) {
            throw new InvalidBindingException(
                sprintf('The binding type "%s" is not supported on this endpoint', $unsupportedBinding)
            );
        }

        throw new InvalidBindingException(
            sprintf(
                'No SAMLRequest or SAMLResponse parameter was found in the HTTP "%s" request parameters',
                $request->getMethod()
            )
        );
    }

    private function isSoapContentType(Request $request): bool
    {
        $contentType = $request->headers->get('Content-Type');
        if ($contentType === null) {
            return false;
        }

        $mediaType = strtolower(trim(explode(';', $contentType)[0]));

        return in_array($mediaType, ['text/xml', 'application/soap+xml'], true);
    }
}
