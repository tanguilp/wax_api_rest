defmodule WaxAPIREST.Callback do
  @moduledoc """
  Behaviour for the callback module that implements various tasks for `WaxAPIREST.Plug`
  """

  alias WaxAPIREST.Types.{
    AuthenticatorTransport,
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialGetOptionsRequest
  }

  @type user_info :: %{
    required(:id) => String.t(),
    optional(:name) => String.t(),
    optional(:display_name) => String.t(),
    optional(:exclude_credentials) => [ServerPublicKeyCredentialDescriptor.flat()]
  }

  @doc """
  Returns the user info required for WebAuthn

  This callback is called during attestation and authentication option request and must
  return the identifier of the user. This identifier is the [user handle of the user account
  entity](https://www.w3.org/TR/webauthn/#sctn-user-credential-params). As stated by the
  [specification](https://www.w3.org/TR/webauthn/#user-handle):

  > A user handle is an opaque byte sequence with a maximum size of 64 bytes.
  > User handles are not meant to be displayed to users. The user handle SHOULD NOT contain
  > personally identifying information about the user, such as a username or e-mail address;

  The callback shall, however, return a string and not a binary as it will not be converted
  to a string.

  It can also returns the name and display name of the user (see
  `t:WaxAPIREST.Callback.user_info/0`). If not provided, it will be defaulted to the
  request's values.

  If the user doesn't exist or a fault occurs when retrieving user information, an exception
  can be raised. Its error message will be displayed in the JSON error response.
  """
  #FIXME: shall we just provide with the conn and not the second param? The risk is that
  # relying on request is not safe if the username is not checked against the session, an
  # OAuth2 token or any other mechanism
  @callback user_info(Plug.Conn.t(), ServerPublicKeyCredentialCreationOptionsRequest) ::
  user_info()
  | no_return()

  @doc """
  Returns the user keys

  Each key can be either a single key identifier or a `{key_identifier, [transport]}` tuple.

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback user_keys(Plug.Conn.t(), ServerPublicKeyCredentialGetOptionsRequest.t()) ::
  %{
    optional(String.t()) =>
      id :: String.t()
      | {id :: String.t, transports :: [AuthenticatorTransport.t()]}
  }

  @doc """
  Save the current attestation or authentication challenge and returns the connection

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback put_challenge(Plug.Conn.t(), Wax.Challenge.t()) ::
  Plug.Conn.t()
  | no_return()

  @doc """
  Returns the current challenge

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback get_challenge(Plug.Conn.t()) :: Wax.Challenge.t() | no_return()

  @doc """
  Saves a new attestation key for a user

  The COSE key can be retrieved in the authenticator data using:

      authenticator_data.attested_credential_data.credential_public_key

  The COSE key is a map of integers (both keys and values). This can be conveniently saved in
  Erlang / Elixir using Erlang's `term_to_binary/1` function (and possibly
  `Base.encode64/1` if the database doesn't accept binary values).

  The signature count can also be checked against the value saved in the database:
  
      authenticator_data.sign_count

  A single user can register several keys. Each key is identified by its `key_id`.

  It returns the connection. This can be used to set a value (cookie...) in it.

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback register_key(
    Plug.Conn.t(), key_id :: String.t(), Wax.AuthenticatorData.t(), Wax.Attestation.result()
  ) :: Plug.Conn.t() | no_return()

  @doc """
  Callback called on `t:Plug.Conn.t/0` upon successful authentication

  Can be used to set a value (cookie...) in the connection.

  If a fault occurs an exception can be raised. Its error message will be displayed in the
  JSON error response.
  """
  @callback on_authentication_success(Plug.Conn.t(), Wax.AuthenticatorData.t()) ::
  Plug.Conn.t()
  | no_return()
end
