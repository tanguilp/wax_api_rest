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
  }) when
    is_binary(clientDataJSON) and
    is_binary(authenticatorData) and
    is_binary(signature) and
    is_binary(userHandle)
  do
    %__MODULE__{
      clientDataJSON: clientDataJSON,
      authenticatorData: authenticatorData,
      signature: signature,
      userHandle: userHandle
    }
  end

  def new(response) do
    if response["clientDataJSON"] == nil or not is_binary(response["clientDataJSON"]) do
      raise Error.MissingField, field: "clientDataJSON"
    end

    if response["authenticatorData"] == nil or not is_binary(response["authenticatorData"]) do
      raise Error.MissingField, field: "authenticatorData"
    end

    if response["signature"] == nil or not is_binary(response["signature"]) do
      raise Error.MissingField, field: "signature"
    end

    if response["userHandle"] == nil or not is_binary(response["userHandle"]) do
      raise Error.MissingField, field: "userHandle"
    end
  end
end
