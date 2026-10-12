# Changelog

## [0.6.0] - 2026-08-26

### Fixed

- `POST /assertion/options` no longer lets the request's `userVerification` value
  override the server's: the new `:user_verification` option (plug option or
  application environment under the `WaxAPIREST` key) takes precedence, so a client
  cannot downgrade a `"required"` user verification policy at authentication time.
  The enforced value is set on the authentication challenge (and therefore verified
  by `Wax.authenticate/6`) and advertised in the options response. The configured
  value is validated: an invalid value is rejected with a 400 error instead of
  silently disabling enforcement. The option is scoped to the authentication
  ceremony: it no longer leaks into registration challenges
- `POST /attestation/result` no longer leaks internal error details: like
  `POST /assertion/result`, it now returns a generic `"registration failed"` error
  message instead of the raw `Wax` exception message
- Failed registration and authentication ceremony results are now logged server-side
  with `Logger` (the generic client-facing error message is kept)
- `WaxAPIREST.Types.AuthenticatorTransport.new/1` no longer corrupts transport values by
  mapping them to attestation conveyance preference values (`"usb"` -> `"none"`,
  `"nfc"` -> `"indirect"`, etc.). Accepted values are returned verbatim and the accepted
  set is extended to the current WebAuthn set: `usb`, `nfc`, `ble`, `smart-card`,
  `hybrid` and `internal` (`lightning` is kept for backward compatibility)
- The `timeout` field of both attestation and assertion options responses is now emitted
  in milliseconds, as mandated by the WebAuthn specification, instead of copying
  `Wax.Challenge`'s server-side validity in seconds (the default challenge now yields
  `timeout: 120000` instead of `timeout: 120`)
- `POST /assertion/options` no longer drops stored credential transports: when a
  `user_keys/1` entry's key data contains a non-empty `:transports` list, it is included
  in the corresponding `allowCredentials` descriptor; otherwise the `transports` member
  is omitted

### Added

- The attestation result request now parses the optional client-reported `transports`
  field (the value of `AuthenticatorAttestationResponse.getTransports()`), accepted both
  nested under the `"response"` object (FIDO server API shape) and at the top level of
  the request body (the nested value wins). Invalid or unknown transport values are
  silently dropped. The parsed list is passed to the new `register_key/5` callback
- New `:authenticator_selection` option (plug option or application environment under
  the `WaxAPIREST` key) to enforce authenticator selection criteria server-side. It
  accepts a `WaxAPIREST.Types.AuthenticatorSelectionCriteria` struct or a map with
  string keys, and takes precedence over the value of the request. Its
  `userVerification` member is also set on the registration challenge, so a configured
  `"required"` value is enforced by `Wax.register/3` when verifying the attestation
  result, not just echoed in the options response
- New `:user_verification` option (plug option or application environment under the
  `WaxAPIREST` key) to enforce the user verification requirement of the
  **authentication** ceremony server-side (for the registration ceremony, use the
  `userVerification` member of the `:authenticator_selection` option)
- The `username` field of the assertion options request
  (`ServerPublicKeyCredentialGetOptionsRequest`) is now optional, so clients performing
  a usernameless (discoverable credential / passkey) flow don't have to send a
  placeholder value. Note that the library performs no user handle based credential
  lookup: credential selection remains entirely the responsibility of the
  `user_keys/1` callback (for instance based on the session)

### Breaking changes

- The `WaxAPIREST.Callback.register_key/4` callback is extended to `register_key/5`;
  the fifth argument is the (possibly empty) list of client-reported transports.
  Existing 4-arity implementations will get a compile-time warning about the missing
  `register_key/5` callback (and a conflicting `@impl` warning if used) and must add
  the extra argument
