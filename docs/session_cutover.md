# Session cutover and rollback

EngineBlock keeps in-flight authentication state in the PHP session: the received AuthnRequest, the response waiting
for consent or Stepup, the consent continuation and similar flow state. This state is stored as serialized PHP objects
that wrap SAML messages.

Releases that change the SAML library or the stored message format cannot read each other's session state. The
saml2 v7 migration is such a release: messages are stored in a new versioned format (`engineblock-saml2-v7/1`) and the
saml2 4.x classes no longer exist. EngineBlock therefore never shares session storage between such releases.

## How sessions are separated

1. **Session cookie name.** The cookie name is configured with the `session_cookie_name` parameter
   (`config/packages/parameters.yml`). The default for this release is `engineblock_session_v7`; previous releases used
   `main`. A browser that still carries the old cookie simply starts a new, empty session.
2. **Namespace marker.** Every session written by this release carries a marker that combines the cookie name and the
   message storage format. A session presented without the expected marker (for example when the cookie name was
   reused, or a rollback wrote to the same storage) is invalidated before any authentication state is read.
3. **Restore guards.** Stored messages in an unknown or older format, or that cannot be parsed, are never used. They
   are reported as a lost session.

In all of these cases the user sees the existing "session lost" feedback page, and can restart the login at the
service provider. EngineBlock does not attempt to convert state written by another release.

## Cutover

1. Announce a short maintenance window. Users who are in the middle of a login when the cutover happens must restart
   it.
2. Optionally drain in-flight flows: stop routing new logins to the old release and wait a few minutes (logins
   normally complete within the session lifetime) before switching all traffic.
3. Deploy the new release with a `session_cookie_name` that has not been used before. The default
   `engineblock_session_v7` is fine for the first cutover.
4. Switch traffic. Expect a short rise in "session lost" feedback and in the log notice
   `Discarding session state that was not written by this release`.

## Rollback

The previous release uses the cookie name `main` and cannot read state written by this release, but it would try to
read it if it found the same session ID in storage.

1. Before switching traffic back, either purge the session storage (for example empty the PHP session save path or
   flush the session store), or configure the previous release with a separate session save path.
2. Switch traffic to the previous release. Users in the middle of a login restart it.

## Roll forward after a rollback

Sessions written by the previous release during the rollback must not reach this release with a cookie name it trusts.
Before deploying again, set `session_cookie_name` to a name that has not been used yet (for example
`engineblock_session_v7_2`). The namespace marker then invalidates any session that was not written by the new
deployment.
