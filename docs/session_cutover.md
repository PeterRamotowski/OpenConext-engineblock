# Session cutover and rollback

EngineBlock keeps in-flight authentication state in the PHP session: the received AuthnRequest, the response waiting
for consent or Stepup, the consent continuation and similar flow state. This state is stored as serialized PHP objects
that wrap SAML messages.

Releases that change the SAML library or the stored message format cannot read each other's session state. The
saml2 v7 migration is such a release: messages are stored in a new versioned format (`engineblock-saml2-v7/1`) and the
saml2 4.x classes no longer exist.

PHP deserializes the complete session as soon as the session starts, before EngineBlock can inspect it. The only way to
prevent one release from deserializing another release's objects is to never let it load that data. Therefore:

- every cutover, rollback and roll forward requires separate or purged session storage: a separate session save path
  or store, or one that is emptied before the switch;
- a cutover or roll forward also requires a fresh `session_cookie_name`. A rollback cannot change the cookie name,
  because the previous release always uses `main`.

A fresh cookie name alone is not enough, because a session ID that is presented under the new cookie name still loads
whatever data shared storage holds for it.

## Safeguards in EngineBlock

These checks limit the damage when the procedure above is not followed. They do not replace it.

1. **Session cookie name.** The cookie name is configured with the `session_cookie_name` parameter
   (`config/packages/parameters.yml`). The default for this release is `engineblock_session_v7`; previous releases used
   `main`. A browser that still carries only the old cookie starts a new, empty session.
2. **Namespace marker.** Every session written by this release carries a marker that combines the cookie name and the
   message storage format. A session without the expected marker is invalidated before EngineBlock uses any
   authentication state from it, and the notice `Discarding session state that was not written by this release` is
   logged. The session data has already been deserialized by then.
3. **Restore guards.** Stored flow state is checked before it is used:
   - State in an unknown or older format, or that is not an object written by this release, produces the "session
     lost" feedback page. The user restarts the login at the service provider.
   - Stored message XML in the current format that cannot be parsed produces the invalid-response feedback page
     (`/authentication/feedback/received-invalid-response`). The parse error is kept as the cause and logged under
     `previous_exceptions`.

EngineBlock does not attempt to convert state written by another release.

## Cutover

1. Announce a short maintenance window. Users who are in the middle of a login when the cutover happens must restart
   it.
2. Optionally drain in-flight flows: stop routing new logins to the old release and wait a few minutes (logins
   normally complete within the session lifetime) before switching all traffic.
3. Deploy the new release with a `session_cookie_name` that has not been used before (the default
   `engineblock_session_v7` is fine for the first cutover) and with session storage that the old release does not use,
   or purge the shared storage at the switch.
4. Switch traffic. Expect a short rise in "session lost" feedback.

## Rollback

The previous release always uses the cookie name `main`, so for a rollback only the storage can be separated.

1. Before switching traffic back, purge the session storage (for example empty the PHP session save path or flush the
   session store), or configure the previous release with its own separate session save path.
2. Switch traffic to the previous release. Users in the middle of a login restart it.

## Roll forward after a rollback

1. Set `session_cookie_name` to a name that has not been used yet (for example `engineblock_session_v7_2`).
2. Purge the session storage, or give this release a session save path that the previous release did not write to.
3. Deploy and switch traffic.
