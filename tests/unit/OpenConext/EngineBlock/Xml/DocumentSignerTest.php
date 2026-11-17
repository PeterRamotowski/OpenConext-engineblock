<?php declare(strict_types=1);

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

namespace OpenConext\EngineBlock\Xml;

use OpenConext\EngineBlock\Exception\RuntimeException;
use OpenConext\EngineBlock\Metadata\X509\X509CertificateFactory;
use OpenConext\EngineBlock\Metadata\X509\X509KeyPair;
use OpenConext\EngineBlock\Metadata\X509\X509PrivateKey;
use OpenConext\EngineBlock\Saml2\Bundle\FakePrivateKeyAgent;
use OpenConext\EngineBlock\Saml2\Bundle\GeneratedKeyPair;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C;
use Surfnet\SamlBundle\PrivateKeyAgent\AlgorithmRegistrar;
use Surfnet\SamlBundle\Service\SigningService;

class DocumentSignerTest extends TestCase
{
    public function test_signs_xml_documents()
    {
        $signer = new DocumentSigner(new SigningService(new KeyLoader(), new PrivateKeyLoader()));
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<!-- https://support.example.org/terms-en -->
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="EB12345" validUntil="2019-10-16T12:41:12Z" cacheDuration="PT604800S" entityID="Test Entity">
   <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="1" />
   </md:SPSSODescriptor>
   <md:Organization>
      <md:OrganizationName xml:lang="en-US">Test Organization</md:OrganizationName>
      <md:OrganizationDisplayName xml:lang="en-US">Test</md:OrganizationDisplayName>
      <md:OrganizationURL xml:lang="en-US">https://examle.org</md:OrganizationURL>
   </md:Organization>
</md:EntityDescriptor>
XML;

        $expextedOutput = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<!-- https://support.example.org/terms-en -->
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="EB12345" validUntil="2019-10-16T12:41:12Z" cacheDuration="PT604800S" entityID="Test Entity">
   <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
         <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
         <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
         <ds:Reference URI="#EB12345">
            <ds:Transforms>
               <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
               <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
            <ds:DigestValue>nM+i0lfnpkNm/iH9c4XsvqUL3PaH+4OPethgW0fzI/Y=</ds:DigestValue>
         </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>NgA0E/bmBWEca3jHMICgKD0RWjIbmMA1haM49v6giRf2ZFldv12CVQAiQUm6xWAmzTBInRXoZTGrpw/njMsAveT7RPzwtJDQQlsxegTuOt/2jeoEMtOfWdTxP70+SbT2wcearTPXvl0MSuPn3PV82i71IcEQGnSBj4bdNqVuDJ24dUEpCqazznRfMNLCqDRHAKk7ZEAEnrpenJEFKOvyt9FjzYk6Mwfi2QjeN9BQb5iFVxiGoVkihkKbs4zw/5VamoR2i39pKwwhg39n++JjS5R+cDYPQfDoWuJ3JR0bXUzDPlhADM4RIP8CZKbVejwg7zNINXhbskd7S1JOfySdKA==</ds:SignatureValue>
      <ds:KeyInfo>
         <ds:X509Data>
            <ds:X509Certificate>MIIDXzCCAkegAwIBAgIJAM4CwNsdIhJ3MA0GCSqGSIb3DQEBBQUAMEYxDzANBgNVBAMMBkVuZ2luZTERMA8GA1UECwwIU2VydmljZXMxEzARBgNVBAoMCk9wZW5Db25leHQxCzAJBgNVBAYTAk5MMB4XDTE0MDUxMjEzMjIxNloXDTI0MDUxMTEzMjIxNlowRjEPMA0GA1UEAwwGRW5naW5lMREwDwYDVQQLDAhTZXJ2aWNlczETMBEGA1UECgwKT3BlbkNvbmV4dDELMAkGA1UEBhMCTkwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2aQ9OYsAASWR/aN5NB2mQqFsBc13uN0nSbjkk1Um8VouGo7OmSM0eiur5my8UvPYth1DXQM6u2wiFq19RtfVZWJOmrzAfVHc9VRj9Xj4T+MVpR4bDWctvxVT1OPm9L23KQKvaqDmUo7uSPsBD36EIH7dFOBydDtSXfZTW0ien+lZr6C4nPuxzDbHJ+Jlo2brieimUBQNetX/ettnAglJ9536sJDkhsa120mkYPhVnvepbOtxPyU5ZDUpDNmMQR2/SORCBJcfvLSVZ4It4O67l6/EJnkFRLerIqOpk/W8jY3USQaLM2WM7sWBGxEFKDVcTFgrOH50Z94K2M/KweY2bAgMBAAGjUDBOMB0GA1UdDgQWBBSewI9OzfzbIxnl6XMkaQkYY1hHPjAfBgNVHSMEGDAWgBSewI9OzfzbIxnl6XMkaQkYY1hHPjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAFfYPZbsYPHz4ypV/aO59do7CtHPnAMWr0NcQt4h9IW8gjihaNHt12V30QtHrVaXejXybB/LaGbPPyA64+l/SeC7ksrRxlitCwFqnws6ISXJaYU0iEFHGUD/cAj1iGloIsOm5IOdb3sdG/SsBv49G8es2wG0rDd0/s2fBVvXd4qUoXzKJAjYk1MFQxnGHomlt67SBrr2QLh+m2VHg+mkdi6yrdm9B9ylF8V55Vl82pPZXxphIRgqdos5YWeALS7dr5dSw9s5smFBxyy8IfCQMxagfNC59w22w2ULC/J7au/oP8ylusuxncxizdR/+5UazzAlOWtkjzaABzzBWM4hEK</ds:X509Certificate>
         </ds:X509Data>
      </ds:KeyInfo>
   </ds:Signature>
   <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="1" />
   </md:SPSSODescriptor>
   <md:Organization>
      <md:OrganizationName xml:lang="en-US">Test Organization</md:OrganizationName>
      <md:OrganizationDisplayName xml:lang="en-US">Test</md:OrganizationDisplayName>
      <md:OrganizationURL xml:lang="en-US">https://examle.org</md:OrganizationURL>
   </md:Organization>
</md:EntityDescriptor>
XML;
        $publicKeyFactory = new X509CertificateFactory();

        // Warning: certificates expire on May 11, 2024
        $publicKey = $publicKeyFactory->fromFile(__DIR__ . '/test.pem.crt');
        $privateKey = new X509PrivateKey(__DIR__ . '/test.pem.key');
        $keyPair = new X509KeyPair($publicKey, $privateKey);

        $output = $signer->sign($xml, $keyPair);

        $this->assertXmlStringEqualsXmlString($expextedOutput, $output);
    }

    public function test_element_to_sign_must_be_second_child()
    {
        $signer = new DocumentSigner(new SigningService(new KeyLoader(), new PrivateKeyLoader()));
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="EB12345" validUntil="2019-10-16T12:41:12Z" cacheDuration="PT604800S" entityID="Test Entity">
   <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="1" />
   </md:SPSSODescriptor>
   <md:Organization>
      <md:OrganizationName xml:lang="en-US">Test Organization</md:OrganizationName>
      <md:OrganizationDisplayName xml:lang="en-US">Test</md:OrganizationDisplayName>
      <md:OrganizationURL xml:lang="en-US">https://examle.org</md:OrganizationURL>
   </md:Organization>
</md:EntityDescriptor>
XML;
        $publicKeyFactory = new X509CertificateFactory();

        // Warning: certificates expire on May 11, 2024
        $publicKey = $publicKeyFactory->fromFile(__DIR__ . '/test.pem.crt');
        $privateKey = new X509PrivateKey(__DIR__ . '/test.pem.key');
        $keyPair = new X509KeyPair($publicKey, $privateKey);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Could not locate root element to sign');
        $output = $signer->sign($xml, $keyPair);
    }

    public function test_an_agent_key_pair_signs_through_the_private_key_agent_without_a_local_key()
    {
        $agent = $this->registerAgent();
        $certificate = (new X509CertificateFactory())->fromFile(GeneratedKeyPair::named('metadata')->certificateFile());

        $output = $this->signer()->sign($this->metadataXml(), X509KeyPair::forPrivateKeyAgent($certificate));

        $this->assertSame(['eb-metadata'], $agent->keysUsedFor('sign'));
        $entityDescriptor = EntityDescriptor::fromXML(DOMDocumentFactory::fromString($output)->documentElement);
        $verifier = (new SignatureAlgorithmFactory())->getAlgorithm(
            C::SIG_RSA_SHA256,
            GeneratedKeyPair::named('metadata')->certificate()->getPublicKey()
        );
        $this->assertInstanceOf(EntityDescriptor::class, $entityDescriptor->verify($verifier));
    }

    public function test_an_agent_outage_fails_metadata_signing_with_redacted_diagnostics()
    {
        $agent = $this->registerAgent();
        $agent->failWithStatus(503);
        $certificate = (new X509CertificateFactory())->fromFile(GeneratedKeyPair::named('metadata')->certificateFile());

        try {
            $this->signer()->sign($this->metadataXml(), X509KeyPair::forPrivateKeyAgent($certificate));
            $this->fail('Metadata signing must fail when the agent is unavailable');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('AgentUnavailableException', $exception->getMessage());
            $this->assertNull($exception->getPrevious());
            $this->assertCount(1, $agent->requests, 'The agent is called once, without retries');
        }
    }

    protected function tearDown(): void
    {
        AlgorithmRegistrar::reset();
    }

    private function registerAgent(): FakePrivateKeyAgent
    {
        $keyPair = GeneratedKeyPair::named('metadata');
        $agent = new FakePrivateKeyAgent(['eb-metadata' => $keyPair->privateKeyPem()]);
        $agent->register([
            'eb-metadata' => ['certificate_file' => $keyPair->certificateFile(), 'token' => 'token', 'operations' => ['sign']],
        ]);

        return $agent;
    }

    private function signer(): DocumentSigner
    {
        return new DocumentSigner(new SigningService(new KeyLoader(), new PrivateKeyLoader()));
    }

    private function metadataXml(): string
    {
        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<!-- https://support.example.org/terms-en -->
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="EB12345" entityID="https://engine.example.org">
   <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="1" />
   </md:SPSSODescriptor>
</md:EntityDescriptor>
XML;
    }
}
