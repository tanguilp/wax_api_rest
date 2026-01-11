defmodule WaxAPIREST.Types.ServerPublicKeyCredential do
  alias WaxAPIREST.Types.{
    Error,
    PublicKeyCredentialType,
    ServerAuthenticatorAssertionResponse,
    ServerAuthenticatorAttestationResponse
  }

  @enforce_keys [:id, :rawId, :response, :type]

  defstruct [
    :id,
    :rawId,
    :response,
    :type,
    :getClientExtensionResults
  ]

  @type t :: %__MODULE__{
    id: String.t(),
    rawId: String.t(),
    response:
      ServerAuthenticatorAttestationResponse.t() | ServerAuthenticatorAssertionResponse.t(),
    type: PublicKeyCredentialType.t(),
    getClientExtensionResults: map() | nil
  }

  # Maximum lengths for input validation (security: prevent DoS via large inputs)
  @max_credential_id_length 1024

  @spec new(map()) :: t() | no_return()
  def new(%{
    "id" => id,
    "rawId" => rawId,
    "response" => response,
    "type" => "public-key" = type
  } = request) when
    is_binary(id) and
    is_binary(rawId) and
    id == rawId
  do
    # Validate credential ID size
    if byte_size(id) > @max_credential_id_length do
      raise Error.InvalidField,
        field: "id",
        value: id,
        reason: "exceeds maximum length of #{@max_credential_id_length} bytes"
    end

    case Base.url_decode64(id, padding: false) do
      {:ok, _} ->
        :ok

      :error ->
        raise Error.InvalidField,
          field: "id",
          value: id,
          reason: "must be url-base64 encoded without padding"
    end

    %__MODULE__{
      id: id,
      rawId: rawId,
      response:
        if response["signature"] do
          ServerAuthenticatorAssertionResponse.new(response)
        else
          ServerAuthenticatorAttestationResponse.new(response)
        end,
      type: type,
      getClientExtensionResults: request["getClientExtensionResults"]
    }
  end

  def new(%{"id" => _, "rawId" => rawId}) do
    raise Error.InvalidField,
      field: "rawId",
      value: rawId,
      reason: "must have the same value as `id`"
  end

  def new(request) do
    if request["id"] == nil or not is_binary(request["id"]) do
      raise Error.MissingField, field: "id"
    end

    if request["rawId"] == nil or not is_binary(request["rawId"]) do
      raise Error.MissingField, field: "rawId"
    end

    if request["type"] == nil, do: raise Error.MissingField, field: "type"

    if request["type"] != "public-key" do
      raise Error.InvalidField,
        field: "type",
        value: request["type"],
        accepted_value: ["public-key"]
    end
  end
end
