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

namespace OpenConext\EngineBlock\Saml2\Message;

use InvalidArgumentException;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\AttributeStatement;
use SimpleSAML\SAML2\XML\saml\AuthnContext;
use SimpleSAML\SAML2\XML\saml\AuthnStatement;
use SimpleSAML\SAML2\XML\saml\Subject;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Extensions;
use SimpleSAML\SAML2\XML\samlp\Response;

/**
 * Rebuilds immutable saml2 v7 elements with changed fields.
 *
 * Every field that is not present in $changes is copied from the original. A rebuilt element is
 * unsigned: a signature of the original never covers the changed element.
 */
final class MessageRebuilder
{
    private const array RESPONSE_FIELDS = [
        'id', 'status', 'issueInstant', 'issuer', 'inResponseTo', 'destination', 'consent', 'extensions', 'assertions',
    ];

    private const array AUTHN_REQUEST_FIELDS = [
        'id', 'issueInstant', 'requestedAuthnContext', 'subject', 'nameIdPolicy', 'conditions', 'forceAuthn',
        'isPassive', 'assertionConsumerServiceURL', 'assertionConsumerServiceIndex', 'protocolBinding',
        'attributeConsumingServiceIndex', 'providerName', 'issuer', 'destination', 'consent', 'extensions', 'scoping',
    ];

    private const array ASSERTION_FIELDS = ['issuer', 'issueInstant', 'id', 'subject', 'conditions', 'statements'];

    private const array AUTHN_STATEMENT_FIELDS = [
        'authnContext', 'authnInstant', 'sessionNotOnOrAfter', 'sessionIndex', 'subjectLocality',
    ];

    public static function response(Response $response, array $changes): Response
    {
        self::assertKnownFields($changes, self::RESPONSE_FIELDS, Response::class);
        $value = self::valueResolver($changes);

        return new Response(
            $value('id', $response->getId()),
            $value('status', $response->getStatus()),
            $value('issueInstant', $response->getIssueInstant()),
            $value('issuer', $response->getIssuer()),
            $value('inResponseTo', $response->getInResponseTo()),
            $value('destination', $response->getDestination()),
            $value('consent', $response->getConsent()),
            $value('extensions', self::extensions($response->getExtensions())),
            $value('assertions', $response->getAssertions()),
        );
    }

    public static function authnRequest(AuthnRequest $request, array $changes): AuthnRequest
    {
        self::assertKnownFields($changes, self::AUTHN_REQUEST_FIELDS, AuthnRequest::class);
        $value = self::valueResolver($changes);

        return new AuthnRequest(
            $value('id', $request->getId()),
            $value('issueInstant', $request->getIssueInstant()),
            $value('requestedAuthnContext', $request->getRequestedAuthnContext()),
            $value('subject', $request->getSubject()),
            $value('nameIdPolicy', $request->getNameIdPolicy()),
            $value('conditions', $request->getConditions()),
            $value('forceAuthn', $request->getForceAuthn()),
            $value('isPassive', $request->getIsPassive()),
            $value('assertionConsumerServiceURL', $request->getAssertionConsumerServiceURL()),
            $value('assertionConsumerServiceIndex', $request->getAssertionConsumerServiceIndex()),
            $value('protocolBinding', $request->getProtocolBinding()),
            $value('attributeConsumingServiceIndex', $request->getAttributeConsumingServiceIndex()),
            $value('providerName', $request->getProviderName()),
            $value('issuer', $request->getIssuer()),
            $value('destination', $request->getDestination()),
            $value('consent', $request->getConsent()),
            $value('extensions', self::extensions($request->getExtensions())),
            $value('scoping', $request->getScoping()),
        );
    }

    public static function assertion(Assertion $assertion, array $changes): Assertion
    {
        self::assertKnownFields($changes, self::ASSERTION_FIELDS, Assertion::class);
        $value = self::valueResolver($changes);

        return new Assertion(
            $value('issuer', $assertion->getIssuer()),
            $value('issueInstant', $assertion->getIssueInstant()),
            $value('id', $assertion->getId()),
            $value('subject', $assertion->getSubject()),
            $value('conditions', $assertion->getConditions()),
            $value('statements', self::statements($assertion)),
        );
    }

    /**
     * All statements of the assertion. saml2 v7 has no public accessor for AuthzDecisionStatements;
     * EngineBlock neither produces nor consumes them.
     */
    public static function statements(Assertion $assertion): array
    {
        return array_merge(
            $assertion->getAuthnStatements(),
            $assertion->getAttributeStatements(),
            $assertion->getStatements(),
        );
    }

    /**
     * Replace the attribute statement(s), keeping all other statements in their order.
     */
    public static function assertionWithAttributeStatement(
        Assertion $assertion,
        ?AttributeStatement $attributeStatement
    ): Assertion {
        $statements = array_values(array_filter(
            self::statements($assertion),
            static fn ($statement) => !$statement instanceof AttributeStatement
        ));
        if ($attributeStatement !== null) {
            $statements[] = $attributeStatement;
        }

        return self::assertion($assertion, ['statements' => $statements]);
    }

    public static function assertionWithSubjectIdentifier(Assertion $assertion, mixed $identifier): Assertion
    {
        $subject = $assertion->getSubject();
        $confirmations = $subject?->getSubjectConfirmation() ?? [];
        if ($identifier === null && $confirmations === []) {
            return self::assertion($assertion, ['subject' => null]);
        }

        return self::assertion($assertion, ['subject' => new Subject($identifier, $confirmations)]);
    }

    /**
     * Rebuild the (first) AuthnStatement of the assertion with changed fields.
     */
    public static function assertionWithAuthnStatement(Assertion $assertion, array $changes): Assertion
    {
        self::assertKnownFields($changes, self::AUTHN_STATEMENT_FIELDS, AuthnStatement::class);
        $value = self::valueResolver($changes);

        $statements = self::statements($assertion);
        foreach ($statements as $index => $statement) {
            if (!$statement instanceof AuthnStatement) {
                continue;
            }
            $statements[$index] = new AuthnStatement(
                $value('authnContext', $statement->getAuthnContext()),
                $value('authnInstant', $statement->getAuthnInstant()),
                $value('sessionNotOnOrAfter', $statement->getSessionNotOnOrAfter()),
                $value('sessionIndex', $statement->getSessionIndex()),
                $value('subjectLocality', $statement->getSubjectLocality()),
            );

            return self::assertion($assertion, ['statements' => $statements]);
        }

        throw new InvalidArgumentException('The assertion has no AuthnStatement');
    }

    public static function authnContext(AuthnContext $authnContext, array $changes): AuthnContext
    {
        $value = self::valueResolver($changes);

        return new AuthnContext(
            $value('authnContextClassRef', $authnContext->getAuthnContextClassRef()),
            $value('authnContextDecl', $authnContext->getAuthnContextDecl()),
            $value('authnContextDeclRef', $authnContext->getAuthnContextDeclRef()),
            $value('authenticatingAuthorities', $authnContext->getAuthenticatingAuthorities()),
        );
    }

    private static function extensions(mixed $extensions): ?Extensions
    {
        return $extensions instanceof Extensions ? $extensions : null;
    }

    private static function valueResolver(array $changes): \Closure
    {
        return static fn (string $field, mixed $original): mixed =>
            array_key_exists($field, $changes) ? $changes[$field] : $original;
    }

    private static function assertKnownFields(array $changes, array $fields, string $class): void
    {
        $unknown = array_diff(array_keys($changes), $fields);
        if ($unknown !== []) {
            throw new InvalidArgumentException(
                sprintf('Unknown field(s) "%s" for %s', implode('", "', $unknown), $class)
            );
        }
    }
}
