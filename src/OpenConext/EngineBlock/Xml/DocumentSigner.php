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

declare(strict_types=1);

namespace OpenConext\EngineBlock\Xml;

use Dom\Element;
use Dom\Node;
use Dom\XMLDocument;
use OpenConext\EngineBlock\Exception\RuntimeException;
use OpenConext\EngineBlock\Metadata\X509\X509KeyPair;
use OpenConext\EngineBlock\Saml2\Bundle\PrivateKeyAgentFailure;
use SimpleSAML\XMLSecurity\Exception\PrivateKeyAgentExceptionInterface;
use Surfnet\SamlBundle\Service\SigningService;
use Surfnet\SamlBundle\Signing\KeyPair;
use Surfnet\SamlBundle\Signing\Signable;
use Throwable;

/**
 * Signs metadata through the SAML bundle's SigningService, with RSA-SHA256 and the selected key pair: a local
 * key pair signs with its private key file, an agent key pair through the Private Key Agent without a local key.
 */
class DocumentSigner implements DocumentSignerInterface
{
    private const NS_XMLNS = 'http://www.w3.org/2000/xmlns/';

    public function __construct(private readonly SigningService $signingService)
    {
    }

    public function sign(string $source, X509KeyPair $signingKeyPair) : string
    {
        // Load the XML to be signed
        try {
            $doc = XMLDocument::createFromString($source);
        } catch (Throwable $exception) {
            throw new RuntimeException('Could not parse XML source', 0, $exception);
        }

        // Find root element to sign. The firstChild is the TOS comment,
        // so need to skip over that.
        $rootNode = $doc->childNodes->item(1);
        if (!$rootNode instanceof Element) {
            throw new RuntimeException("Could not locate root element to sign");
        }

        // xml-security 3.1 loops forever canonicalizing a document element preceded by a comment. Exclusive
        // canonicalization without comments ignores those nodes, so they are detached while signing.
        $leadingNodes = [];
        while ($rootNode->previousSibling !== null) {
            $leadingNodes[] = $doc->removeChild($rootNode->previousSibling);
        }

        $rootDeclaredDs = $rootNode->hasAttributeNS(self::NS_XMLNS, 'ds');

        try {
            $this->signingService->sign($this->signable($rootNode), $this->toBundleKeyPair($signingKeyPair));
        } catch (PrivateKeyAgentExceptionInterface $failure) {
            // Not chained: only the redacted agent diagnostic is kept. There is no local-key fallback.
            throw new RuntimeException(sprintf(
                'The private key agent could not sign the metadata (%s)',
                PrivateKeyAgentFailure::describe($failure)
            ));
        }

        // xml-security declares xmlns:ds on the signed element; keep the declaration on ds:Signature as before.
        // Exclusive canonicalization only emits visibly used namespaces, so the signature is unaffected.
        if (!$rootDeclaredDs && $rootNode->hasAttributeNS(self::NS_XMLNS, 'ds')) {
            $rootNode->removeAttributeNS(self::NS_XMLNS, 'ds');
        }

        foreach (array_reverse($leadingNodes) as $leadingNode) {
            $doc->insertBefore($leadingNode, $rootNode);
        }

        $signedXml = $doc->saveXml();
        if ($signedXml === false) {
            throw new RuntimeException('Could not serialize the signed XML document');
        }

        return $signedXml;
    }

    /**
     * The signature becomes the first child of the root element.
     */
    private function signable(Element $rootNode): Signable
    {
        return new class ($rootNode) implements Signable {
            public function __construct(private readonly Element $rootNode)
            {
            }

            public function getRootDomElement(): Element
            {
                return $this->rootNode;
            }

            public function getAppendBeforeNode(): ?Node
            {
                return $this->rootNode->firstChild;
            }
        };
    }

    private function toBundleKeyPair(X509KeyPair $signingKeyPair): KeyPair
    {
        $certificateFile = $signingKeyPair->getCertificate()->getFilePath();
        if ($certificateFile === null) {
            throw new RuntimeException('The metadata signing certificate was not loaded from a file');
        }

        $keyPair = new KeyPair();
        $keyPair->publicKeyFile = $certificateFile;

        if ($signingKeyPair->usesPrivateKeyAgent()) {
            $keyPair->usePrivateKeyAgent = true;
            $keyPair->privateKeyFile = null;

            return $keyPair;
        }

        $privateKey = $signingKeyPair->getPrivateKey();
        if ($privateKey === null) {
            throw new RuntimeException('The metadata signing key pair has no private key');
        }
        $keyPair->privateKeyFile = $privateKey->getFilePath();

        return $keyPair;
    }
}
