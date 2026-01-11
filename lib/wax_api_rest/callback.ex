defmodule WaxAPIREST.Callback do
  @moduledoc """
  Behaviour for the callback module that implements various tasks for `WaxAPIREST.Plug`

  Note that users **shall** be authenticated in some manner when registering - relying on
  the provided username would be insecure as it would allow an attacker to register new
  key (and then authenticate) for any existing account.
  """

  alias WaxAPIREST.Types.AuthenticatorTransport

  @typedoc """
  User information

  The returned `id` field must be URL base64 encoded no longer than 64 bytes.
  """
  @type user_info :: %{
    required(:id) => String.t(),
    optional(:name) => String.t(),
    optional(:display_name) => String.t()
  }

  @typedoc """
  Key data
  """
  @type key_data :: %{
    required(:cose_key) => Wax.CoseKey.t(),
    optional(:transports) => [AuthenticatorTransport.t()] | nil,
    optional(:sign_count) => non_neg_integer()
  }

  @typedoc """
  List of registered user keys
  """
  @type user_keys() ::
  [{credential_id :: Wax.CredentialId.t(), key_data()}]
  | %{optional(credential_id :: Wax.CredentialId.t()) => key_data()}

  @doc """
  Returns the user info required for WebAuthn

  This callback is called during attestation and authentication option request and must
  return the identifier of the user. This identifier is the
  [user handle of the user account entity](https://www.w3.org/TR/webauthn/#sctn-user-credential-params).
  As stated by the [specification](https://www.w3.org/TR/webauthn/#user-handle):

  > A user handle is an opaque byte sequence with a maximum size of 64 bytes.
  > User handles are not meant to be displayed to users. The user handle SHOULD NOT contain
  > personally identifying information about the user, such as a username or e-mail address;

  The callback shall, however, return a string and not a binary as it will not be converted
  to a string.

  It can also returns the name and display name of the user (see
  `t:WaxAPIREST.Callback.user_info/0`). If not provided, it will be defaulted to the
  request's values.

  If the user doesn't exist or a fault occurs when retrieving user information, an
  exception can be raised. Its error message will be displayed in the JSON error response.
  """
  @callback user_info(conn :: Plug.Conn.t()) :: user_info() | no_return()

  @doc """
  Returns the user keys

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback user_keys(conn :: Plug.Conn.t()) :: user_keys()

  @doc """
  Save the current attestation or authentication challenge and returns the connection

  **Security**: Challenges MUST be stored with a timestamp and expired after a reasonable
  timeout (recommended: 5 minutes). The `get_challenge/1` callback should validate expiration
  before returning challenges.

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback put_challenge(
    conn :: Plug.Conn.t(),
    challenge :: Wax.Challenge.t()
  ) :: Plug.Conn.t() | no_return()

  @doc """
  Returns the current challenge

  **Security**: Challenges MUST be expired after a reasonable timeout (recommended: 5 minutes).
  This callback should validate that the challenge has not expired before returning it.
  Expired challenges should raise an exception to prevent replay attacks.

  If a fault occurs or the challenge has expired, an exception can be raised. Its error
  message will be displayed in the JSON error response.
  """
  @callback get_challenge(conn :: Plug.Conn.t()) :: Wax.Challenge.t() | no_return()

  @doc """
  Invalidates the current challenge to prevent replay attacks

  This callback is called after successful authentication or registration to ensure
  that challenges cannot be reused. Challenges MUST be invalidated after use to prevent
  replay attacks.

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback invalidate_challenge(conn :: Plug.Conn.t()) :: Plug.Conn.t() | no_return()

  @doc """
  Saves a new attestation key for a user

  The COSE key can be retrieved in the authenticator data using:

      authenticator_data.attested_credential_data.credential_public_key

  The COSE key is a map of integers (both keys and values). This can be conveniently saved
  in Erlang / Elixir using Erlang's `term_to_binary/1` function (and possibly
  `Base.encode64/1` if the database doesn't accept binary values).

  The signature count can also be checked against the value saved in the database:

      authenticator_data.sign_count

  A single user can register several keys. Each key is identified by its `key_id`.

  It returns the connection. This can be used to set a value (cookie...) in it.

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback register_key(
    conn :: Plug.Conn.t(),
    credential_id :: Wax.CredentialId.t(),
    authenticator_data :: Wax.AuthenticatorData.t(),
    attestation_result :: Wax.Attestation.result()
  ) :: Plug.Conn.t() | no_return()

  @doc """
  Callback called on `t:Plug.Conn.t/0` upon successful authentication

  Can be used to set a value (cookie...) in the connection.

  **Signature counter** update should be performed at this step, if supported.

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback on_authentication_success(
    conn :: Plug.Conn.t(),
    credential_id :: Wax.CredentialId.t(),
    authenticator_data :: Wax.AuthenticatorData.t()
  ) ::  Plug.Conn.t() | no_return()
end
