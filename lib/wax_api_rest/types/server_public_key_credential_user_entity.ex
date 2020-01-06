defmodule WaxAPIREST.Types.ServerPublicKeyCredentialUserEntity do
  @derive Jason.Encoder

  @enforce_keys [:id, :name, :displayName]

  defstruct [
    :id,
    :name,
    :displayName
  ]

  @type t :: %__MODULE__{
    id: String.t(),
    name: String.t(),
    displayName: String.t()
  }

  @spec new(String.t(), String.t(), String.t()) :: t()
  def new(name, id, display_name) do
    %__MODULE__{
      name: name,
      id: id,
      displayName: display_name
    }
  end
end