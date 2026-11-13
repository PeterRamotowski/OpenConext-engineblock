<?php declare(strict_types=1);

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

namespace OpenConext\EngineBlock\Saml2\Bundle;

use OpenConext\EngineBlock\Exception\RuntimeException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;

/**
 * HTTP-Redirect encoding for AuthnRequests that policy does not require to be signed.
 *
 * The bundle's query builder always signs. Use this encoder only when no signature is required; a failure to
 * sign must never fall back to it. It emits no SigAlg or Signature and never contacts the private key agent.
 */
final class UnsignedRedirectEncoder
{
    public function buildQuery(AuthnRequest $request, ?string $relayState = null): string
    {
        $deflated = gzdeflate($request->getUnsignedXML());
        if ($deflated === false) {
            throw new RuntimeException('Could not deflate the AuthnRequest for the HTTP-Redirect binding');
        }

        $parameters = [AuthnRequest::PARAMETER_REQUEST => base64_encode($deflated)];
        if ($relayState !== null && $relayState !== '') {
            $parameters[AuthnRequest::PARAMETER_RELAY_STATE] = $relayState;
        }

        return http_build_query($parameters);
    }

    public function buildUrl(AuthnRequest $request, ?string $relayState = null): string
    {
        $destination = $request->getDestination();
        $separator = str_contains($destination, '?') ? '&' : '?';

        return $destination . $separator . $this->buildQuery($request, $relayState);
    }
}
