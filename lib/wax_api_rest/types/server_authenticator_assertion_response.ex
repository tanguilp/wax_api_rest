defmodule WaxAPIREST.Types.ServerAuthenticatorAssertionResponse do
  alias WaxAPIREST.Types.Error

  @enforce_keys [:clientDataJSON, :authenticatorData, :signature, :userHandle]

  defstruct [
    :clientDataJSON,
    :authenticatorData,
    :signature,
    :userHandle
  ]

  @type t :: %__MODULE__{
    clientDataJSON: String.t(),
    authenticatorData: String.t(),
    signature: String.t(),
    userHandle: String.t()
  }

  @spec new(map()) :: t()
  def new(%{
    "clientDataJSON" => clientDataJSON,
    "authenticatorData" => authenticatorData,
    "signature" => signature,
    "userHandle" => userHandle
  }) do
    %__MODULE__{
      clientDataJSON: clientDataJSON,
      authenticatorData: authenticatorData,
      signature: signature,
      userHandle: userHandle
    }
  end

  def new(response) do
    if response["clientDataJSON"] == nil, do: raise Error.MissingField, field: "clientDataJSON"
    if response["authenticatorData"] == nil, do: raise Error.MissingField, field: "authenticatorData"
    if response["signature"] == nil, do: raise Error.MissingField, field: "signature"
    if response["userHandle"] == nil, do: raise Error.MissingField, field: "userHandle"
  end
end
