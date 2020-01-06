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

  @spec new(map()) :: t() | no_return()
  def new(%{
    "id" => id,
    "rawId" => rawId,
    "response" => response,
    "type" => "public-key" = type
  } = request) do
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

  def new(request) do
    if request["id"] == nil, do: raise Error.MissingField, field: "id"

    if request["rawId"] == nil, do: raise Error.MissingField, field: "rawId"

    if request["type"] == nil, do: raise Error.MissingField, field: "type"

    if request["type"] != "public-key" do
      raise Error.InvalidField,
        field: "type",
        value: request["type"],
        accepted_value: ["public-key"]
    end
  end
end
