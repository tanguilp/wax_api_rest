defmodule WaxAPIREST.Plug do
  @moduledoc """
  A plug that exposes the FIDO2 REST API
  [7. Transport Binding Profil](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#transport-binding-profile).

  ## Usage

  In a Phoenix router, forward a route to the `WaxAPIREST.Plug`:

      defmodule MyApp.Router do
        use Phoenix.Router

        forward "/webauthn", WaxAPIREST.Plug, callback: MyApp.WebAuthnCallbackModule
      end

  If you're using `Plug.Router`:

      defmodule MyApp.Router do
        use Plug.Router

        forward "/webauthn", to: WaxAPIREST.Plug, callback: MyApp.WebAuthnCallbackModule
      end

  ## Callback module

  An implementation of the `WaxAPIREST.Callback` module must be provided as an option or
  in the configuration file.

  ## Options

  In addition to Wax's options (`t:Wax.opt/0`), the `t:opts/0` can be used specifically
  with this plug.

  For instance, using Phoenix:

      defmodule MyApp.Router do
        use Phoenix.Router

        forward "/webauthn", WaxAPIREST.Plug, [
          callback_module: MyApp.WebAuthnCallbackModule,
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
  - `:callback_module` [**mandatory**]: the callback module, no default
  - `:rp_name`: a [human-palatable identifier for the Relying Party](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialentity).
  If not present, defaults to the RP id (`Wax` option `:rp_id`)
  - `:pub_key_cred_params`: the list of allowed credential algorithms. Defaults to
  `[-36, -35, -7]` which are ES512, ES384 and ES256 in this order of precedence. These
  values have been chosen using the following security analysis:
  [Security Concerns Surrounding WebAuthn: Don't Implement ECDAA (Yet)](https://paragonie.com/blog/2018/08/security-concerns-surrounding-webauthn-don-t-implement-ecdaa-yet)
  - `:attestation_conveyance_preference`: the attestation conveyance preference. Defaults
  to the value of the request or, if absent, to `"none"`

  The options can be configured (in order of precedence):
  - through options passed as a parameter to the plug router
  - in the configuration file (under the `WaxAPIREST` key)
  """
  @type opt ::
          {:callback_module, module()}
          | {:rp_name, String.t()}
          | {:pub_key_cred_params, [Wax.CoseKey.cose_alg()]}
          | {:attestation_conveyance_preference, AttestationConveyancePreference.t()}

  # Maximum lengths for input validation (security: prevent DoS via large inputs)
  # ~64KB for base64-encoded data
  @max_base64_string_length 65536

  plug(:match)
  plug(:dispatch, builder_opts())
  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)

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
      |> Enum.map(fn
        {key_id, %{transports: transports}} ->
          ServerPublicKeyCredentialDescriptor.new(key_id, transports)

        {key_id, _} ->
          ServerPublicKeyCredentialDescriptor.new(key_id)
      end)

    response =
      ServerPublicKeyCredentialCreationOptionsResponse.new(
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

    # Validate input sizes to prevent DoS attacks
    if byte_size(registration_request.response.attestationObject) > @max_base64_string_length do
      raise WaxAPIREST.Types.Error.InvalidField,
        field: "attestationObject",
        value: registration_request.response.attestationObject,
        reason: "exceeds maximum length of #{@max_base64_string_length} bytes"
    end

    if byte_size(registration_request.response.clientDataJSON) > @max_base64_string_length do
      raise WaxAPIREST.Types.Error.InvalidField,
        field: "clientDataJSON",
        value: registration_request.response.clientDataJSON,
        reason: "exceeds maximum length of #{@max_base64_string_length} bytes"
    end

    attestation_object =
      case Base.url_decode64(registration_request.response.attestationObject, padding: false) do
        {:ok, decoded} ->
          decoded

        :error ->
          raise WaxAPIREST.Types.Error.InvalidField,
            field: "attestationObject",
            value: registration_request.response.attestationObject,
            reason: "invalid base64url encoding"
      end

    client_data_json =
      case Base.url_decode64(registration_request.response.clientDataJSON, padding: false) do
        {:ok, decoded} ->
          decoded

        :error ->
          raise WaxAPIREST.Types.Error.InvalidField,
            field: "clientDataJSON",
            value: registration_request.response.clientDataJSON,
            reason: "invalid base64url encoding"
      end

    Wax.register(
      attestation_object,
      client_data_json,
      challenge
    )
    |> case do
      {:ok, {authenticator_data, attestation_result}} ->
        conn
        |> callback_module.register_key(
          registration_request.rawId,
          authenticator_data,
          attestation_result
        )
        |> callback_module.invalidate_challenge()
        |> send_json(200, %{
          "status" => "ok",
          "errorMessage" => ""
        })

      {:error, e} ->
        send_json(conn, 400, %{"status" => "failed", "errorMessage" => Exception.message(e)})
    end
  end

  post "/assertion/options" do
    callback_module = callback_module(opts)

    creation_request = ServerPublicKeyCredentialGetOptionsRequest.new(conn.body_params)

    allow_credentials =
      conn
      |> callback_module.user_keys()
      |> Enum.map(fn {cred_id, %{cose_key: cose_key}} -> {cred_id, cose_key} end)

    challenge_opts =
      opts
      |> Keyword.put(:user_verification, creation_request.userVerification)
      |> Keyword.put(:allow_credentials, allow_credentials)

    challenge = Wax.new_authentication_challenge(challenge_opts)

    response =
      ServerPublicKeyCredentialGetOptionsResponse.new(
        creation_request,
        challenge,
        Enum.map(allow_credentials, fn {key_id, _} -> key_id end),
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

    # Validate input sizes to prevent DoS attacks
    if byte_size(authn_request.response.authenticatorData) > @max_base64_string_length do
      raise WaxAPIREST.Types.Error.InvalidField,
        field: "authenticatorData",
        value: authn_request.response.authenticatorData,
        reason: "exceeds maximum length of #{@max_base64_string_length} bytes"
    end

    if byte_size(authn_request.response.signature) > @max_base64_string_length do
      raise WaxAPIREST.Types.Error.InvalidField,
        field: "signature",
        value: authn_request.response.signature,
        reason: "exceeds maximum length of #{@max_base64_string_length} bytes"
    end

    if byte_size(authn_request.response.clientDataJSON) > @max_base64_string_length do
      raise WaxAPIREST.Types.Error.InvalidField,
        field: "clientDataJSON",
        value: authn_request.response.clientDataJSON,
        reason: "exceeds maximum length of #{@max_base64_string_length} bytes"
    end

    authenticator_data =
      case Base.url_decode64(authn_request.response.authenticatorData, padding: false) do
        {:ok, decoded} ->
          decoded

        :error ->
          raise WaxAPIREST.Types.Error.InvalidField,
            field: "authenticatorData",
            value: authn_request.response.authenticatorData,
            reason: "invalid base64url encoding"
      end

    signature =
      case Base.url_decode64(authn_request.response.signature, padding: false) do
        {:ok, decoded} ->
          decoded

        :error ->
          raise WaxAPIREST.Types.Error.InvalidField,
            field: "signature",
            value: authn_request.response.signature,
            reason: "invalid base64url encoding"
      end

    client_data_json =
      case Base.url_decode64(authn_request.response.clientDataJSON, padding: false) do
        {:ok, decoded} ->
          decoded

        :error ->
          raise WaxAPIREST.Types.Error.InvalidField,
            field: "clientDataJSON",
            value: authn_request.response.clientDataJSON,
            reason: "invalid base64url encoding"
      end

    Wax.authenticate(
      authn_request.rawId,
      authenticator_data,
      signature,
      client_data_json,
      challenge
    )
    |> case do
      {:ok, authenticator_data} ->
        user_keys = callback_module.user_keys(conn)

        if sign_count_valid?(authn_request.rawId, authenticator_data, user_keys) do
          conn
          |> callback_module.on_authentication_success(
            authn_request.rawId,
            authenticator_data
          )
          |> callback_module.invalidate_challenge()
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

      {:error, e} ->
        send_json(conn, 400, %{"status" => "failed", "errorMessage" => sanitize_error_message(e)})
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

          _ ->
            false
        end
      )

    new_sign_count = authenticator_data.sign_count

    # If we have a saved sign count > 0, or the new sign count > 0, validate strictly
    if (saved_sign_count != nil and saved_sign_count > 0) or new_sign_count > 0 do
      # Compare against saved count, defaulting to 0 if nil
      new_sign_count > (saved_sign_count || 0)
    else
      # If both are 0 or nil, allow (for authenticators that don't support sign count)
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
    # Sanitize error messages to prevent information disclosure
    # Only expose user-safe error messages; detailed errors are logged server-side
    message =
      case error do
        %WaxAPIREST.Types.Error.MissingField{field: field} ->
          "missing mandatory field `#{sanitize_field_name(field)}`"

        %WaxAPIREST.Types.Error.InvalidField{field: field, reason: reason}
        when not is_nil(reason) ->
          "invalid field `#{sanitize_field_name(field)}`: #{sanitize_reason(reason)}"

        %WaxAPIREST.Types.Error.InvalidField{field: field, accepted_value: accepted_value}
        when is_list(accepted_value) ->
          "invalid field `#{sanitize_field_name(field)}`, must be one of: #{Enum.join(accepted_value, ", ")}"

        %WaxAPIREST.Types.Error.InvalidField{field: field} ->
          "invalid field `#{sanitize_field_name(field)}`"

        %_{} ->
          # For other exceptions, use a generic message to avoid leaking internal details
          "request validation failed"

        _ ->
          "request validation failed"
      end

    resp =
      %{status: "failed", errorMessage: message}
      |> Jason.encode!()

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(400, resp)
  end

  # Sanitize field names to prevent injection of malicious content
  defp sanitize_field_name(field) when is_binary(field) do
    # Remove any non-printable characters and limit length
    field
    |> String.replace(~r/[^\x20-\x7E]/, "")
    |> String.slice(0, 100)
  end

  defp sanitize_field_name(_), do: "field"

  # Sanitize reason strings to prevent information disclosure
  defp sanitize_reason(reason) when is_binary(reason) do
    # Remove any non-printable characters and limit length
    reason
    |> String.replace(~r/[^\x20-\x7E]/, "")
    |> String.slice(0, 200)
  end

  defp sanitize_reason(_), do: "invalid value"

  # Sanitize error messages from external libraries to prevent information disclosure
  defp sanitize_error_message(error) do
    case error do
      %WaxAPIREST.Types.Error.MissingField{} = e ->
        # Use the error function for our own error types
        error(%Plug.Conn{}, e)
        |> Map.get(:resp_body)
        |> Jason.decode!()
        |> Map.get("errorMessage")

      %WaxAPIREST.Types.Error.InvalidField{} = e ->
        # Use the error function for our own error types
        error(%Plug.Conn{}, e)
        |> Map.get(:resp_body)
        |> Jason.decode!()
        |> Map.get("errorMessage")

      %_{} ->
        # For other exceptions, use a generic message to avoid leaking internal details
        "authentication failed"

      _ ->
        "authentication failed"
    end
  end

  @spec callback_module(opts()) :: module()
  def callback_module(opts) do
    opts[:callback_module] ||
      Application.get_env(WaxAPIREST, :callback_module) ||
      raise "callback module not configured"
  end

  defimpl Jason.Encoder,
    for: [
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
