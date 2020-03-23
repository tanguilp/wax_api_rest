defmodule WaxAPIREST.Types.ServerAuthenticatorAttestationResponse do
  alias WaxAPIREST.Types.Error

  @enforce_keys [:clientDataJSON, :attestationObject]

  defstruct [
    :clientDataJSON,
    :attestationObject,
  ]

  @type t :: %__MODULE__{
    clientDataJSON: String.t(),
    attestationObject: String.t()
  }

  @spec new(map()) :: t() | no_return()
  def new(%{
    "clientDataJSON" => clientDataJSON,
    "attestationObject" => attestationObject
  }) when is_binary(clientDataJSON) and is_binary(attestationObject)
  do
    %__MODULE__{
      clientDataJSON: clientDataJSON,
      attestationObject: attestationObject,
    }
  end

  def new(response) do
    if response["clientDataJSON"] == nil or not is_binary(response["clientDataJSON"]) do
      raise Error.MissingField, field: "clientDataJSON"
    end

    if response["attestationObject"] == nil or not is_binary(response["attestationObject"]) do
      raise Error.MissingField, field: "attestationObject"
    end
  end
end
