defmodule WaxAPIREST.Plug do
  @moduledoc """
  A plug that exposes the FIDO2 REST API
  [7. Transport Binding Profil](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#transport-binding-profile).

  ## Usage

  In a Phoenix router, forward a route to the `WaxAPIREST.Plug`:

      defmodule MyApp.Router do
        use Phoenix.Router

        forward "/webauthn", WaxAPIREST.Plug
      end

  If you're using `Plug.Router`:

      defmodule MyApp.Router do
        use Plug.Router

        forward "/webauthn", to: WaxAPIREST.Plug
      end

  ## Callback module

  An implementation of the `WaxAPIREST.Callback` module must be provided as an option or
  in the configuration file.

  Do not use the `WaxAPIREST.Callback.Test` implementation module at all, it is designed for
  testing with the FIDO2 official test suite and won't even work in other contexts.

  ## Options

  In addition to Wax's options (`t:Wax.opt/0`), the `t:opts/0` can be used specifically with this
  plug.

  For instance, using Phoenix:

      defmodule MyApp.Router do
        use Phoenix.Router

        forward "/webauthn", WaxAPIREST.Plug, [
          callback_module: MyApp.WebAuthn,
          rp_name: "My site",
          pub_key_cred_params: [-36, -35, -7, -259, -258, -257] # allows RSA algs
        ]
      end
  """

  use Plug.Router
  use Plug.ErrorHandler

  alias WaxAPIREST.Types.{
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PubKeyCredParams,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredential,
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredentialUserEntity
  }

  @type opts :: [Wax.opt() | opt()]

  @typedoc """
  In addition to the Wax options, this library defines the following options:
  - `:callback_module`: the callback module. Defaults to `WaxAPIREST.Callback.Test`
  - `:rp_name`: a [human-palatable identifier for the Relying Party](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialentity).
  If not present, defaults to the RP id (`Wax` option `rp_id`)
  - `:pub_key_cred_params`: the list of allowed credential algorithms. Defaults to
  `[-36, -35, -7]` which are ES512, ES384 and ES256 in this order of precedence. These values
  have been chosen using the following security analysis:
  [Security Concerns Surrounding WebAuthn: Don't Implement ECDAA (Yet)](https://paragonie.com/blog/2018/08/security-concerns-surrounding-webauthn-don-t-implement-ecdaa-yet)
  - `:attestation_conveyance_preference`: the attestation conveyance preference. Defaults to
  the value of the request or, if absent, to `"none"`

  The options can be configured (in order of precedence):
  - through options passed as a parameter to the plug router
  - in the configuration file (under the `WaxAPIREST` key)

  If an configuration option is not provided, it falls back to a default value.
  """
  @type opt ::
  {:callback_module, module()}
  | {:rp_name, String.t()}
  | {:pub_key_cred_params, [Wax.CoseKey.cose_alg()]}
  | {:attestation_conveyance_preference, AttestationConveyancePreference.t()}

  plug :match
  plug :dispatch, builder_opts()
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  post "/attestation/options" do
    callback_module = callback_module(opts)

    creation_request = ServerPublicKeyCredentialCreationOptionsRequest.new(conn.body_params)

    challenge =
      opts
      |> Keyword.put(:attestation, creation_request.attestation)
      |> Wax.new_registration_challenge()

    user_info = callback_module.user_info(conn)

    exclude_credentials =
      callback_module.user_keys(conn)
      |> Enum.map(
        fn
          {key_id, %{transports: transports}} ->
            ServerPublicKeyCredentialDescriptor.new(key_id, transports)

          {key_id, _} ->
            ServerPublicKeyCredentialDescriptor.new(key_id)
        end
      )

    response = ServerPublicKeyCredentialCreationOptionsResponse.new(
      creation_request,
      challenge,
      user_info,
      Keyword.put(opts, :exclude_credentials, exclude_credentials)
    )

    conn
    |> callback_module.put_challenge(challenge)
    |> send_json(200, response)
  end

  post "/attestation/result" do
    callback_module = callback_module(opts)

    challenge = callback_module.get_challenge(conn)

    registration_request = ServerPublicKeyCredential.new(conn.body_params)

    Wax.register(
      Base.url_decode64!(registration_request.response.attestationObject, padding: false),
      Base.url_decode64!(registration_request.response.clientDataJSON, padding: false),
      challenge
    )
    |> case do
      {:ok, {authenticator_data, attestation_result}} ->
        callback_module.register_key(
          conn,
          registration_request.rawId,
          authenticator_data,
          attestation_result
        )
        |> send_json(200, %{
          "status" => "ok",
          "errorMessage" => ""
        })

      {:error, reason} ->
        send_json(conn, 400, %{
          "status" => "failed",
          "errorMessage" => reason |> Atom.to_string() |> String.replace("_", " ")
        })
    end
  end

  post "/assertion/options" do
    callback_module = callback_module(opts)

    creation_request = ServerPublicKeyCredentialGetOptionsRequest.new(conn.body_params)

    keys = callback_module.user_keys(conn)

    challenge_opts =
      Keyword.put(opts, :user_verification, creation_request.userVerification)

    challenge =
      keys
      |> Enum.map(fn {cred_id, %{cose_key: cose_key}} -> {cred_id, cose_key} end)
      |> Wax.new_authentication_challenge(challenge_opts)

    response = ServerPublicKeyCredentialGetOptionsResponse.new(
      creation_request,
      challenge,
      Enum.map(keys, fn {key_id, _} -> key_id end),
      opts
    )

    conn
    |> callback_module.put_challenge(challenge)
    |> send_json(200, response)
  end

  post "/assertion/result" do
    callback_module = callback_module(opts)

    challenge = callback_module.get_challenge(conn)

    authn_request = ServerPublicKeyCredential.new(conn.body_params)

    Wax.authenticate(
      authn_request.rawId,
      Base.url_decode64!(authn_request.response.authenticatorData, padding: false),
      Base.url_decode64!(authn_request.response.signature, padding: false),
      Base.url_decode64!(authn_request.response.clientDataJSON, padding: false),
      challenge
    )
    |> case do
      {:ok, authenticator_data} ->
        user_keys = callback_module.user_keys(conn)

        if sign_count_valid?(authn_request.rawId, authenticator_data, user_keys) do
          callback_module.on_authentication_success(
            conn,
            authn_request.rawId,
            authenticator_data
          )
          |> send_json(200, %{
            "status" => "ok",
            "errorMessage" => ""
          })
        else
          send_json(conn, 400, %{
            "status" => "failed",
            "errorMessage" => "invalid sign count"
          })
        end

      {:error, reason} ->
        send_json(conn, 400, %{
          "status" => "failed",
          "errorMessage" => reason |> Atom.to_string() |> String.replace("_", " ")
        })
    end
  end

  @spec sign_count_valid?(
    Wax.CredentialId.t(),
    Wax.AuthenticatorData.t(),
    WaxAPIREST.Callback.user_keys()
  ) :: boolean()
  defp sign_count_valid?(raw_id, authenticator_data, user_keys) do
    saved_sign_count =
      Enum.find_value(
        user_keys,
        fn
          {^raw_id, %{sign_count: sign_count}} ->
            sign_count

          _ -> false
        end
      )

    new_sign_count = authenticator_data.sign_count

    if saved_sign_count != nil and saved_sign_count > 0 or new_sign_count > 0 do
      new_sign_count > saved_sign_count
    else
      true
    end
  end

  defp send_json(conn, status, response) do
    body = Jason.encode!(response)

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> send_resp(status, body)
  end

  def handle_errors(conn, %{kind: _kind, reason: e, stack: _stack}) do
    error(conn, e)
  end

  @spec error(Plug.Conn.t(), Exception.t() | any()) :: Plug.Conn.t()
  defp error(conn, error) do
    message =
      case error do
        %_{} ->
          Exception.message(error)

        _ ->
          to_string(error)
      end

    resp =
      %{status: "failed", errorMessage: message}
      |> Jason.encode!()

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(400, resp)
  end

  @spec callback_module(opts()) :: module()
  def callback_module(opts) do
    opts[:callback_module]
    || Application.get_env(WaxAPIREST, :callback_module)
    || WaxAPIREST.Callback.Test
  end

  defimpl Jason.Encoder, for: [
    AuthenticatorSelectionCriteria,
    PubKeyCredParams,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredentialUserEntity
  ] do
    def encode(struct, opts) do
      struct
      |> Map.from_struct()
      |> Enum.filter(fn {_k, v} -> v != nil end)
      |> Enum.into(%{})
      |> Jason.Encode.map(opts)
    end
  end
end
