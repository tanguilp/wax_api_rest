defmodule WaxAPIREST.Types.ServerPublicKeyCredentialDescriptor do
  alias WaxAPIREST.Types.{
    AuthenticatorTransport,
    PublicKeyCredentialType
  }

  @enforce_keys [:type, :id]

  defstruct [
    :type,
    :id,
    :transports
  ]

  @type t :: %__MODULE__{
    type: PublicKeyCredentialType.t(),
    id: String.t(),
    transports: [AuthenticatorTransport.t()] | nil
  }

  @typedoc """
  A tuple-based representation of `t:ServerPublicKeyCredentialDescriptor/0`

  This representation is designed to make it easier to use it with an external data store
  such as a database, that has no knowledge of Elixir's data structures
  """
  @type flat ::
  id :: String.t()
  | {id :: String.t(), [AuthenticatorTransport.t()]}

  @spec new(String.t(), [AuthenticatorTransport.t()] | nil) :: t()
  def new(id, transports \\ nil) when is_binary(id) do
    %__MODULE__{
      type: PublicKeyCredentialType.new("public-key"),
      id: id,
      transports:
        if transports do
          Enum.map(transports, &AuthenticatorTransport.new/1)
        end
    }
  end
end
