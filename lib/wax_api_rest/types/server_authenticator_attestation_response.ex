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
  }) do
    %__MODULE__{
      clientDataJSON: clientDataJSON,
      attestationObject: attestationObject,
    }
  end

  def new(response) do
    if response["clientDataJSON"] == nil, do: raise Error.MissingField, field: "clientDataJSON"
    if response["attestationObject"] == nil, do: raise Error.MissingField, field: "attestationObject"
  end
end
