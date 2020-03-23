defmodule WaxAPIREST.Types.ServerPublicKeyCredentialUserEntity do
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
  def new(name, id, display_name) when
    is_binary(name) and is_binary(id) and is_binary(display_name)
  do
    %__MODULE__{
      name: name,
      id: id,
      displayName: display_name
    }
  end
end
