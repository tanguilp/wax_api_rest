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
  {:callback, module()}
  | {:rp_name, String.t()}
  | {:pub_key_cred_params, [Wax.CoseKey.cose_alg()]}
  | {:attestation_conveyance_preference, AttestationConveyancePreference.t()}

  plug(:match)
  plug(:dispatch)
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  post "/attestation/options" do
    callback_module = callback_module(opts)

    request = ServerPublicKeyCredentialCreationOptionsRequest.new(conn.body_params)

    challenge = Wax.new_registration_challenge([
      user_verified_required: Application.get_env(:wax, :user_verified_required)
    ])

    user_info = callback_module.user_info(conn, request)

    response = ServerPublicKeyCredentialCreationOptionsResponse.new(
      request,
      challenge,
      user_info,
      opts
    )

    conn
    |> callback_module.put_challenge(challenge)
    |> send_json(200, response)
  end

  post "/attestation/result" do
    callback_module = callback_module(opts)

    challenge = callback_module.get_challenge(conn)

    request = ServerPublicKeyCredential.new(conn.body_params)

    Wax.register(
      Base.url_decode64!(request.response.attestationObject, padding: false),
      Base.url_decode64!(request.response.clientDataJSON, padding: false),
      challenge
    )
    |> case do
      {:ok, {authenticator_data, attestation_result}} ->
        callback_module.register_key(conn, request.rawId, authenticator_data, attestation_result)
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

    request = ServerPublicKeyCredentialGetOptionsRequest.new(conn.body_params)

    keys = callback_module.user_keys(conn, request)

    challenge = Wax.new_authentication_challenge(
      Enum.map(
        keys,
        fn 
          {key_id, %{} = cose_key} ->
            {key_id, cose_key}

          {key_id, {cose_key, _transports}} ->
            {key_id, cose_key}
        end
      ),
      [user_verified_required: Application.get_env(:wax, :user_verified_required)]
    )

    response = ServerPublicKeyCredentialGetOptionsResponse.new(
      request,
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

    request = ServerPublicKeyCredential.new(conn.body_params)

    Wax.authenticate(
      request.rawId,
      Base.url_decode64!(request.response.authenticatorData, padding: false),
      Base.url_decode64!(request.response.signature, padding: false),
      Base.url_decode64!(request.response.clientDataJSON, padding: false),
      challenge
    )
    |> case do
      {:ok, authenticator_data} ->
        callback_module.on_authentication_success(conn, authenticator_data)
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

  defp send_json(conn, status, response) do
    body = Jason.encode!(response)

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> send_resp(status, body)
  end

  def handle_errors(conn, %{kind: :error, reason: e, stack: _stack}) do
    error(conn, e)
  end

  @spec error(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t()
  defp error(conn, e) do
    resp =
      %{status: "failed", errorMessage: Exception.message(e)}
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
