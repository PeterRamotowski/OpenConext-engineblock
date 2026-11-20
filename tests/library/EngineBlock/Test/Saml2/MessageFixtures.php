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

use OpenConext\EngineBlock\Saml2\Message\AttributeMapper;
use OpenConext\EngineBlock\Saml2\Message\Saml2Value;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\AuthnContext;
use SimpleSAML\SAML2\XML\saml\AuthnContextClassRef;
use SimpleSAML\SAML2\XML\saml\AuthnStatement;
use SimpleSAML\SAML2\XML\saml\NameID;
use SimpleSAML\SAML2\XML\saml\Subject;
use SimpleSAML\SAML2\XML\saml\SubjectConfirmation;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSchema\Type\NCNameValue;

/**
 * Builds saml2 v7 messages for tests. Options that are omitted get a valid default.
 */
final class EngineBlock_Test_Saml2_MessageFixtures
{
    /**
     * @param array{id?: string, issueInstant?: int, issuer?: ?string, destination?: ?string, acsUrl?: ?string,
     *     protocolBinding?: ?string, forceAuthn?: bool, isPassive?: bool} $options
     */
    public static function authnRequest(array $options = []): AuthnRequest
    {
        $issuer = $options['issuer'] ?? null;
        $destination = $options['destination'] ?? null;
        $acsUrl = $options['acsUrl'] ?? null;
        $protocolBinding = $options['protocolBinding'] ?? null;

        return new AuthnRequest(
            id: IDValue::fromString($options['id'] ?? '_request'),
            issueInstant: Saml2Value::dateTime($options['issueInstant'] ?? 0),
            forceAuthn: isset($options['forceAuthn']) ? BooleanValue::fromBoolean($options['forceAuthn']) : null,
            isPassive: isset($options['isPassive']) ? BooleanValue::fromBoolean($options['isPassive']) : null,
            assertionConsumerServiceURL: $acsUrl === null ? null : SAMLAnyURIValue::fromString($acsUrl),
            protocolBinding: $protocolBinding === null ? null : SAMLAnyURIValue::fromString($protocolBinding),
            issuer: $issuer === null ? null : Saml2Value::issuer($issuer),
            destination: $destination === null ? null : SAMLAnyURIValue::fromString($destination),
        );
    }

    /**
     * @param array $options see authnRequest(), plus 'classRefs' => string[] for the RequestedAuthnContext
     */
    public static function annotatedAuthnRequest(
        array $options = [],
        ?string $relayState = null
    ): EngineBlock_Saml2_AuthnRequestAnnotationDecorator {
        $request = new EngineBlock_Saml2_AuthnRequestAnnotationDecorator(self::authnRequest($options), $relayState);
        if (!empty($options['classRefs'])) {
            $request->setRequestedAuthnContext(['AuthnContextClassRef' => $options['classRefs']]);
        }

        return $request;
    }

    /**
     * @param array{id?: string, issueInstant?: int, issuer?: string, nameId?: NameID|string|null,
     *     nameIdFormat?: ?string, attributes?: array<string, array>, classRef?: ?string,
     *     authnInstant?: int} $options
     */
    public static function assertion(array $options = []): Assertion
    {
        $nameId = $options['nameId'] ?? null;
        if (is_string($nameId)) {
            $nameId = Saml2Value::nameId($nameId, $options['nameIdFormat'] ?? Constants::NAMEID_TRANSIENT);
        }

        $statements = [];
        if (isset($options['classRef'])) {
            $statements[] = new AuthnStatement(
                new AuthnContext(
                    new AuthnContextClassRef(SAMLAnyURIValue::fromString($options['classRef'])),
                    null,
                    null,
                ),
                Saml2Value::dateTime($options['authnInstant'] ?? 0),
            );
        }
        $attributeStatement = AttributeMapper::toStatement(
            $options['attributes'] ?? [],
            Constants::NAMEFORMAT_URI
        );
        if ($attributeStatement !== null) {
            $statements[] = $attributeStatement;
        }

        return new Assertion(
            Saml2Value::issuer($options['issuer'] ?? 'https://idp.example.org'),
            Saml2Value::dateTime($options['issueInstant'] ?? 0),
            IDValue::fromString($options['id'] ?? '_assertion'),
            new Subject($nameId, [new SubjectConfirmation(SAMLAnyURIValue::fromString(Constants::CM_BEARER))]),
            null,
            $statements,
        );
    }

    /**
     * @param array{id?: string, issueInstant?: int, issuer?: ?string, inResponseTo?: ?string,
     *     destination?: ?string, status?: array, assertions?: Assertion[], assertion?: array} $options
     *     'assertion' holds the assertion() options for the single default assertion.
     */
    public static function response(array $options = []): Response
    {
        $issuer = array_key_exists('issuer', $options) ? $options['issuer'] : 'https://idp.example.org';
        $inResponseTo = $options['inResponseTo'] ?? null;
        $destination = $options['destination'] ?? null;

        return new Response(
            id: IDValue::fromString($options['id'] ?? '_response'),
            status: EngineBlock_Saml2_ResponseAnnotationDecorator::createStatus(
                $options['status'] ?? ['Code' => Constants::STATUS_SUCCESS]
            ),
            issueInstant: Saml2Value::dateTime($options['issueInstant'] ?? 0),
            issuer: $issuer === null ? null : Saml2Value::issuer($issuer),
            inResponseTo: $inResponseTo === null ? null : NCNameValue::fromString($inResponseTo),
            destination: $destination === null ? null : SAMLAnyURIValue::fromString($destination),
            assertions: $options['assertions'] ?? [self::assertion($options['assertion'] ?? [])],
        );
    }

    public static function annotatedResponse(
        array $options = [],
        ?string $relayState = null
    ): EngineBlock_Saml2_ResponseAnnotationDecorator {
        return new EngineBlock_Saml2_ResponseAnnotationDecorator(self::response($options), $relayState);
    }
}
