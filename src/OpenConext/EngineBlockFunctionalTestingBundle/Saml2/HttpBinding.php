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

namespace OpenConext\EngineBlockFunctionalTestingBundle\Saml2;

use DOMDocument;
use RuntimeException;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Minimal SAML 2.0 HTTP-Redirect and HTTP-POST binding support for the mock entities.
 */
final class HttpBinding
{
    public const PARAMETER_REQUEST = 'SAMLRequest';
    public const PARAMETER_RESPONSE = 'SAMLResponse';
    public const PARAMETER_RELAY_STATE = 'RelayState';
    public const PARAMETER_SIGNATURE_ALGORITHM = 'SigAlg';
    public const PARAMETER_SIGNATURE = 'Signature';

    private const ID_PREFIX = 'OPENCONEXT_ETS_';

    public static function generateId(): string
    {
        return self::ID_PREFIX . random_int(0, 100000000);
    }

    /**
     * Build the HTTP-Redirect binding URL, with a query signature (SAML bindings 3.4.4.1) when a signer is given.
     */
    public static function redirectUrl(
        string $destination,
        string $parameter,
        string $xml,
        ?string $relayState = null,
        ?SignatureAlgorithmInterface $signer = null
    ): string {
        $query = $parameter . '=' . urlencode(base64_encode(gzdeflate($xml)));
        if ($relayState !== null) {
            $query .= '&' . self::PARAMETER_RELAY_STATE . '=' . urlencode($relayState);
        }

        if ($signer !== null) {
            $query .= '&' . self::PARAMETER_SIGNATURE_ALGORITHM . '=' . urlencode($signer->getAlgorithmId());
            $query .= '&' . self::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode($signer->sign($query)));
        }

        return $destination . (str_contains($destination, '?') ? '&' : '?') . $query;
    }

    /**
     * Receive a SAML message from an HTTP-POST or HTTP-Redirect binding request.
     *
     * @return array{parameter: string, xml: string, relayState: ?string}
     */
    public static function receive(Request $request): array
    {
        if ($request->isMethod(Request::METHOD_POST)) {
            $bag = $request->request;
            $inflate = false;
        } elseif ($request->isMethod(Request::METHOD_GET)) {
            $bag = $request->query;
            $inflate = true;
        } else {
            throw new RuntimeException(sprintf('Unsupported HTTP method "%s"', $request->getMethod()));
        }

        foreach ([self::PARAMETER_REQUEST, self::PARAMETER_RESPONSE] as $parameter) {
            if (!$bag->has($parameter)) {
                continue;
            }

            $xml = base64_decode($bag->getString($parameter), true);
            if ($xml === false) {
                throw new RuntimeException(sprintf('Unable to base64 decode the "%s" parameter', $parameter));
            }

            if ($inflate) {
                $xml = @gzinflate($xml);
                if ($xml === false) {
                    throw new RuntimeException(sprintf('Unable to inflate the "%s" parameter', $parameter));
                }
            }

            $relayState = $bag->has(self::PARAMETER_RELAY_STATE) ? $bag->getString(self::PARAMETER_RELAY_STATE) : null;

            return ['parameter' => $parameter, 'xml' => $xml, 'relayState' => $relayState];
        }

        throw new RuntimeException('No SAMLRequest or SAMLResponse parameter found');
    }

    /**
     * The (debug) page that makes the browser POST the given data to the given URL.
     */
    public static function postForm(string $url, array $data = []): Response
    {
        $formData = '';
        foreach ($data as $name => $value) {
            $value = htmlentities((string) $value, ENT_COMPAT, 'utf-8');
            $formData .= "            <input name=\"$name\" type=\"text\" value=\"$value\" />" . PHP_EOL;
        }

        if (isset($data[self::PARAMETER_REQUEST])) {
            $data['authnRequestXml'] = self::formatXml(base64_decode($data[self::PARAMETER_REQUEST]));
        }
        if (!isset($data['authnRequestXml'])) {
            $data['authnRequestXml'] = 'N/A';
        }

        $responseDebug = '';
        if (isset($data[self::PARAMETER_RESPONSE])) {
            $responseXml = self::formatXml(base64_decode($data[self::PARAMETER_RESPONSE]));
            $responseDebug = '<pre id="responseDebug">' . htmlentities($responseXml, ENT_QUOTES, 'utf-8') . '</pre>';
        }

        return new Response(<<<HTML
<html>
    <head>
        <title>Redirecting...</title>
    </head>
    <body>
        <pre id="authnRequestXml">{$data['authnRequestXml']}</pre>
        $responseDebug
        <form id="postform" action="{$url}" method="post">
            $formData

            <input type="submit" value="GO" />
        </form>
        <script>setTimeout(function() {document.getElementById('postform').submit();}, 1500);</script>
    </body>
</html>
HTML
        );
    }

    public static function formatXml(string $xml): string
    {
        $dom = new DOMDocument();
        $dom->preserveWhiteSpace = false;
        $dom->loadXML($xml);
        $dom->formatOutput = true;

        return $dom->saveXML();
    }
}
