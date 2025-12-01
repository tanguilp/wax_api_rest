# WaxAPIREST

REST API for [Wax](https://github.com/tanguilp/wax)

A plug that exposes the FIDO2 REST API
[7. Transport Binding Profil](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#transport-binding-profile).

This `Plug` has been created mainly for use by
[WaxFidoTestSuiteServer](https://github.com/tanguilp/wax_fido_test_suite_server), but
could be useful for those who want to implement WebAuthn authentication using
javascript to retrieve challenges. Feedback would be appreciated, especially on the
callback module.

## Installation

```elixir
def deps do
  [
    {:wax_api_rest, "~> 0.4.0"}
  ]
end
```

## Usage

In a Phoenix router, forward a route to the `WaxAPIREST.Plug`:

```elixir
defmodule MyApp.Router do
  use Phoenix.Router

  forward "/webauthn", WaxAPIREST.Plug, callback: MyApp.WebAuthnCallbackModule
end
```

If you're using `Plug.Router`:

```elixir
defmodule MyApp.Router do
  use Plug.Router

  forward "/webauthn", to: WaxAPIREST.Plug, callback: MyApp.WebAuthnCallbackModule
end
```

## Callback module

An implementation of the `WaxAPIREST.Callback` module must be provided as an option or
in the configuration file.

This callback is responsible for:
- returning the current user's information (id, display name...)
- returning the current user's registered WebAuthn keys
- saving backend (for instance in the cookie session)
- registering new WebAuthn keys
- setting authentication status once authenticated

Refer to the callback module for more information.

An example implementation can be found in the
[WaxFidoTestSuiteServer](https://github.com/tanguilp/wax_fido_test_suite_server/blob/master/lib/wax_fido_test_suite_server/user_key_callback_impl.ex)
project (but don't use it as-is).

## Options

In addition to Wax's options (`t:Wax.opt/0`), the following options can be used
specifically with this plug:
- `:callback_module` [**mandatory**]: the callback module
- `:rp_name`: a [human-palatable identifier for the Relying Party](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialentity).
If not present, defaults to the RP id (`Wax` option `:rp_id`)
- `:pub_key_cred_params`: the list of allowed credential algorithms. Defaults to
`[-36, -35, -7]` which are ES512, ES384 and ES256 in this order of precedence. These
values have been chosen using the following security analysis:
[Security Concerns Surrounding WebAuthn: Don't Implement ECDAA (Yet)](https://paragonie.com/blog/2018/08/security-concerns-surrounding-webauthn-don-t-implement-ecdaa-yet)
- `:attestation_conveyance_preference`: the attestation conveyance preference. Defaults to
the value of the request or, if absent, to `"none"`

For instance, using Phoenix:

    defmodule MyApp.Router do
      use Phoenix.Router

      forward "/webauthn", WaxAPIREST.Plug, [
        callback_module: MyApp.WebAuthnCallbackModule,
        rp_name: "My site",
        pub_key_cred_params: [-36, -35, -7, -259, -258, -257] # allows RSA algs
      ]
    end

See `t:WaxAPIREST.Plug.opt/0` for more information, including option precedence rules.

## Security Considerations

### Rate Limiting

**Important**: This library does not implement rate limiting. Applications using this
library **must** implement rate limiting to prevent:

- Brute-force authentication attempts
- Challenge generation spam
- Resource exhaustion attacks

Consider using libraries like `PlugAttack` or similar rate limiting solutions:

```elixir
defmodule MyApp.Router do
  use Phoenix.Router

  # Add rate limiting before forwarding to WaxAPIREST.Plug
  forward "/webauthn", WaxAPIREST.Plug, callback: MyApp.WebAuthnCallbackModule
end
```

Recommended rate limits:
- Challenge generation endpoints (`/attestation/options`, `/assertion/options`):
  Limit to reasonable per-user/IP rates (e.g., 10 requests per minute)
- Authentication/registration endpoints (`/attestation/result`, `/assertion/result`):
  Limit to prevent brute-force attacks (e.g., 5 attempts per minute per credential)

### CSRF Protection

While WebAuthn responses are cryptographically signed and validated, applications should
still implement CSRF protection if using cookie-based sessions. This provides defense in
depth and protects against potential implementation vulnerabilities.

Consider using CSRF token protection for POST endpoints:

```elixir
defmodule MyApp.Router do
  use Phoenix.Router

  # Add CSRF protection
  plug :protect_from_forgery

  forward "/webauthn", WaxAPIREST.Plug, callback: MyApp.WebAuthnCallbackModule
end
```

Note: CSRF protection is especially important if your application uses cookie-based
session management for challenge storage or user identification.
