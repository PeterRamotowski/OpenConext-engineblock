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

use Dom\Element;
use RuntimeException;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\XMLSchema\Type\AnyURIValue;
use SimpleSAML\XMLSchema\Type\Base64BinaryValue;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSchema\Type\StringValue;
use SimpleSAML\XMLSecurity\Alg\Encryption\EncryptionAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\SymmetricKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate as X509CertificateKey;
use SimpleSAML\XMLSecurity\Type\DigestValue as DigestValueType;
use SimpleSAML\XMLSecurity\XML\ds\CanonicalizationMethod;
use SimpleSAML\XMLSecurity\XML\ds\DigestMethod;
use SimpleSAML\XMLSecurity\XML\ds\DigestValue;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\KeyName;
use SimpleSAML\XMLSecurity\XML\ds\Reference;
use SimpleSAML\XMLSecurity\XML\ds\Signature;
use SimpleSAML\XMLSecurity\XML\ds\SignatureMethod;
use SimpleSAML\XMLSecurity\XML\ds\SignatureValue;
use SimpleSAML\XMLSecurity\XML\ds\SignedInfo;
use SimpleSAML\XMLSecurity\XML\ds\Transform;
use SimpleSAML\XMLSecurity\XML\ds\Transforms;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use SimpleSAML\XMLSecurity\XML\xenc\CipherData;
use SimpleSAML\XMLSecurity\XML\xenc\CipherValue;
use SimpleSAML\XMLSecurity\XML\xenc\EncryptedData;
use SimpleSAML\XMLSecurity\XML\xenc\EncryptedKey;
use SimpleSAML\XMLSecurity\XML\xenc\EncryptionMethod;

/**
 * Signing and encryption of (raw) SAML DOM elements for the mock entities.
 *
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects) Builds XML signature and encryption elements for fixtures.
 *
 * The mocks sign and encrypt the serialized DOM instead of the saml2 v7 objects, so the XML can contain values
 * saml2 v7 refuses to model (e.g. an invalid ACS location or AuthnContextClassRef) that EngineBlock must reject.
 */
final class XmlSecurity
{
    private const C14N = C::C14N_EXCLUSIVE_WITHOUT_COMMENTS;

    public static function signer(string $privateKeyPem, string $algorithm = C::SIG_RSA_SHA256): SignatureAlgorithmInterface
    {
        return (new SignatureAlgorithmFactory())->getAlgorithm($algorithm, PrivateKey::fromFile($privateKeyPem));
    }

    public static function verifier(string $certificatePem, string $algorithm = C::SIG_RSA_SHA256): SignatureAlgorithmInterface
    {
        return (new SignatureAlgorithmFactory())->getAlgorithm(
            $algorithm,
            self::certificate($certificatePem)->getPublicKey()
        );
    }

    public static function certificate(string $certificate): X509CertificateKey
    {
        return new X509CertificateKey(PEM::fromString(self::certificatePem($certificate)));
    }

    /**
     * Accepts a PEM certificate or bare base64 certificate data and returns a PEM certificate.
     */
    public static function certificatePem(string $certificate): string
    {
        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(self::certificateData($certificate), 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    /**
     * Accepts a PEM certificate or bare base64 certificate data and returns the bare base64 certificate data.
     */
    public static function certificateData(string $certificate): string
    {
        return preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $certificate);
    }

    public static function keyInfo(string $certificateData, ?string $keyName = null, ?string $id = null): KeyInfo
    {
        $info = [];
        if ($keyName !== null) {
            $info[] = new KeyName(StringValue::fromString($keyName));
        }
        $info[] = new X509Data([
            new X509Certificate(Base64BinaryValue::fromString(self::certificateData($certificateData))),
        ]);

        return new KeyInfo($info, $id === null ? null : IDValue::fromString($id));
    }

    /**
     * Add an enveloped XML signature (exclusive c14n) to the element, placed directly after its saml:Issuer.
     *
     * @SuppressWarnings(PHPMD.UndefinedVariable) The digest table is a public static dependency property.
     * @SuppressWarnings(PHPMD.CamelCaseVariableName) The dependency names the digest table DIGEST_ALGORITHMS.
     */
    public static function signEnveloped(
        Element $element,
        SignatureAlgorithmInterface $signer,
        ?KeyInfo $keyInfo = null
    ): void {
        $id = $element->getAttribute('ID');
        if ($id === null || $id === '') {
            throw new RuntimeException(sprintf('Unable to sign "%s" without an ID attribute', $element->localName));
        }

        $digestAlgorithm = $signer->getDigest();
        $transforms = new Transforms([
            new Transform(AnyURIValue::fromString(C::XMLDSIG_ENVELOPED)),
            new Transform(AnyURIValue::fromString(self::C14N)),
        ]);
        $digest = hash(C::$DIGEST_ALGORITHMS[$digestAlgorithm], $element->C14N(true, false), true);

        $signedInfo = new SignedInfo(
            new CanonicalizationMethod(AnyURIValue::fromString(self::C14N)),
            new SignatureMethod(AnyURIValue::fromString($signer->getAlgorithmId())),
            [
                new Reference(
                    new DigestMethod(AnyURIValue::fromString($digestAlgorithm)),
                    new DigestValue(DigestValueType::fromString(base64_encode($digest))),
                    $transforms,
                    null,
                    null,
                    AnyURIValue::fromString('#' . $id),
                ),
            ],
        );

        $signatureValue = base64_encode($signer->sign($signedInfo->canonicalize(self::C14N)));
        $signature = new Signature(
            $signedInfo,
            new SignatureValue(Base64BinaryValue::fromString($signatureValue)),
            $keyInfo,
        );

        $signatureElement = $signature->toXML($element);
        $issuer = self::firstChildElement($element, Constants::NS_SAML, 'Issuer');
        $element->insertBefore($signatureElement, $issuer !== null ? $issuer->nextSibling : $element->firstChild);
    }

    /**
     * Encrypt a (standalone, possibly signed) assertion like saml2 4.x did: AES-128-CBC, with the session key
     * transported with RSA-OAEP to the certificate, or directly with a shared (symmetric) key.
     * The key transport algorithm is used without explicit OAEP parameters.
     */
    public static function encryptAssertion(
        Element $assertion,
        ?string $certificate,
        ?string $sharedKey,
        string $keyTransportAlgorithm = C::KEY_TRANSPORT_OAEP_MGF1P
    ): Element {
        $plaintext = $assertion->ownerDocument->saveXml($assertion);
        $blockCipher = new EncryptionMethod(AnyURIValue::fromString(C::BLOCK_ENC_AES128));

        if ($certificate !== null) {
            $sessionKey = SymmetricKey::generate(16);
            $keyTransport = (new KeyTransportAlgorithmFactory())->getAlgorithm(
                $keyTransportAlgorithm,
                self::certificate($certificate)->getPublicKey()
            );
            $keyInfo = new KeyInfo([
                EncryptedKey::fromKey(
                    $sessionKey,
                    $keyTransport,
                    new EncryptionMethod(AnyURIValue::fromString($keyTransportAlgorithm)),
                ),
            ]);
        } elseif ($sharedKey !== null) {
            // saml2 4.x used AES-128-CBC with (the first 16 bytes of) the shared key
            $sessionKey = new SymmetricKey(substr(str_pad($sharedKey, 16, "\0"), 0, 16));
            $keyInfo = null;
        } else {
            throw new RuntimeException('Unable to encrypt the assertion without a certificate or shared key');
        }

        $encryptor = (new EncryptionAlgorithmFactory())->getAlgorithm(C::BLOCK_ENC_AES128, $sessionKey);
        $encryptedData = new EncryptedData(
            new CipherData(new CipherValue(Base64BinaryValue::fromString(base64_encode($encryptor->encrypt($plaintext))))),
            null,
            AnyURIValue::fromString(C::XMLENC_ELEMENT),
            null,
            null,
            $blockCipher,
            $keyInfo,
        );

        return (new EncryptedAssertion($encryptedData))->toXML();
    }

    /**
     * Verify the signature of an HTTP-Redirect binding query (SAML bindings 3.4.4.1).
     */
    public static function verifyRedirectSignature(
        string $signedQuery,
        string $signature,
        string $certificate,
        string $algorithm
    ): bool {
        return self::verifier($certificate, $algorithm)->verify($signedQuery, $signature);
    }

    public static function firstChildElement(Element $element, string $namespace, string $localName): ?Element
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element && $child->namespaceURI === $namespace && $child->localName === $localName) {
                return $child;
            }
        }

        return null;
    }
}
