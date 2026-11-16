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

namespace OpenConext\EngineBlockFunctionalTestingBundle\Mock;

use OpenConext\EngineBlockFunctionalTestingBundle\Saml2\XmlSecurity;
use RuntimeException;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\EntityIDValue;
use SimpleSAML\SAML2\Type\KeyTypesValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIListValue;
use SimpleSAML\SAML2\XML\md\AbstractRoleDescriptorType;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\SAML2\XML\md\KeyDescriptor;

/**
 * A mock entity (IdP / SP) with its configuration.
 *
 * The configuration is plain data (scalars, arrays, PEM and XML strings) so the mock can be serialized into the
 * file based DataStore that is shared between the Behat process and the web process.
 */
abstract class AbstractMockEntityRole
{
    public const KEY_ID = 'CONEXT-ETS-KEY-SNAKEOIL';
    public const KEY_NAME = 'snakeoil';

    protected $name;

    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * @param array{entityId: string, certData: string, privateKeyPem: string} $config
     */
    public function __construct($name, array $config)
    {
        $this->name = $name;
        $this->config = $config;
    }

    public function entityId()
    {
        return $this->config['entityId'];
    }

    public function setEntityId($entityId)
    {
        $this->config['entityId'] = $entityId;
        return $this;
    }

    /**
     * The metadata of the mock entity.
     */
    public function getEntityDescriptor(): EntityDescriptor
    {
        return new EntityDescriptor(
            entityId: EntityIDValue::fromString($this->entityId()),
            roleDescriptor: [$this->buildRoleDescriptor([$this->buildSigningKeyDescriptor()])],
        );
    }

    /**
     * @param KeyDescriptor[] $keyDescriptors
     */
    abstract protected function buildRoleDescriptor(array $keyDescriptors): AbstractRoleDescriptorType;

    protected function protocolSupportEnumeration(): SAMLAnyURIListValue
    {
        return SAMLAnyURIListValue::fromString(Constants::NS_SAMLP);
    }

    private function buildSigningKeyDescriptor(): KeyDescriptor
    {
        return new KeyDescriptor(
            XmlSecurity::keyInfo($this->publicKeyCertData(), self::KEY_NAME, self::KEY_ID),
            KeyTypesValue::fromString('signing'),
        );
    }

    /**
     * The (base64 encoded DER) certificate data, without PEM envelope.
     */
    public function publicKeyCertData()
    {
        if (empty($this->config['certData'])) {
            throw new RuntimeException('Mock entity does not have a certificate');
        }

        return $this->config['certData'];
    }

    public function setCertificate($certificateFile)
    {
        $this->config['certData'] = XmlSecurity::certificateData($this->readFile($certificateFile));
    }

    public function setPrivateKey($privateKeyFile)
    {
        $this->config['privateKeyPem'] = $this->readFile($privateKeyFile);
    }

    public function getPrivateKeyPem()
    {
        if (empty($this->config['privateKeyPem'])) {
            throw new RuntimeException('Mock entity does not have a private key');
        }

        return $this->config['privateKeyPem'];
    }

    protected function readFile($filePath)
    {
        return file_get_contents($this->findFile($filePath));
    }

    protected function findFile($filePath)
    {
        if (file_exists($filePath)) {
            return $filePath;
        }

        $componentPath = __DIR__ . '/../../../../';
        $fullFilePath = realpath($componentPath . $filePath);
        if (file_exists($fullFilePath)) {
            return $fullFilePath;
        }

        $pathFromRoot = ENGINEBLOCK_FOLDER_ROOT . $filePath;
        if (file_exists($pathFromRoot)) {
            return $pathFromRoot;
        }

        throw new RuntimeException(sprintf('Unable to find file: "%s" ("%s")', $filePath, $fullFilePath));
    }
}
