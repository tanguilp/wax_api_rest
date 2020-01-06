defmodule WaxAPIREST.Plug do
  @moduledoc """
  # WIP - do not use
  """

  use Plug.Router
  use Plug.ErrorHandler

  alias WaxAPIREST.Types.{
    AttestationConveyancePreference,
    PublicKeyCredentialType,
    ServerPublicKeyCredential,
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse
  }

  @type opts :: [Wax.opt() | opt()]

  @typedoc """
  In addition to the Wax options, this library defines the following options:
  - `:rp_name`: a [human-palatable identifier for the Relying Party]
  (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialentity). If not present, defaults
  to the RP id (`Wax` option `rp_id`)
  - `:pub_key_cred_params`: the list of allowed credential algorithms. Defaults to ES512,
  ES384 and ES256 in thois order of precedence. These values have been chosen following the
  following security analysis:
  [Security Concerns Surrounding WebAuthn: Don't Implement ECDAA (Yet)]
  (https://paragonie.com/blog/2018/08/security-concerns-surrounding-webauthn-don-t-implement-ecdaa-yet)
  - `:attestation_conveyance_preference`: the attestation conveyance preference
  """
  @type opt ::
  {:rp_name, String.t()}
  | {:pub_key_cred_params, [{PublicKeyCredentialType.t(), integer()}]}
  | {:attestation_conveyance_preference, AttestationConveyancePreference.t()}

  plug(:match)
  plug(:dispatch)
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  post "/attestation/options" do
    callback_module = opts[:callback_module] || WaxAPIREST.Callback.Test

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
    callback_module = opts[:callback_module] || WaxAPIREST.Callback.Test

    challenge = callback_module.get_challenge(conn)

    request = ServerPublicKeyCredential.new(conn.body_params)

    Wax.register(
      request.response.attestationObject,
      request.response.clientDataJSON,
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
    callback_module = opts[:callback_module] || WaxAPIREST.Callback.Test

    request = ServerPublicKeyCredentialGetOptionsRequest.new(conn.body_params)

    challenge = Wax.new_registration_challenge([
      user_verified_required: Application.get_env(:wax, :user_verified_required)
    ])

    key_ids =
      Enum.map(
        callback_module.user_keys(conn, request),
        fn
          {id, {_cose_key, transports}} ->
            {id, transports}

          {id, _cose_key} ->
            id
        end)

    response = ServerPublicKeyCredentialGetOptionsResponse.new(
      request,
      challenge,
      key_ids,
      opts
    )

    conn
    |> callback_module.put_challenge(challenge)
    |> send_json(200, response)
  end

  post "/assertion/result" do
    callback_module = opts[:callback_module] || WaxAPIREST.Callback.Test

    challenge = callback_module.get_challenge(conn)

    request = ServerPublicKeyCredential.new(conn.body_params)

    Wax.authenticate(
      request.rawId,
      Base.url_decode64!(request.response.authenticatorData),
      Base.url_decode64!(request.response.signature),
      request.response.clientDataJSON,
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

  def handle_errors(conn, %{kind: :throw, reason: e, stack: _stack}) do
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
end
