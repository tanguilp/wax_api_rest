defmodule WaxAPIREST.Types.PublicKeyCredentialRpEntity do
  @enforce_keys [:name]

  @derive Jason.Encoder

  defstruct [
    :name,
    :id
  ]

  @type t :: %__MODULE__{
    name: String.t(),
    id: String.t() | nil
  }

  @spec new(String.t(), String.t() | nil) :: t()
  def new(name, id \\ nil) do
    %__MODULE__{
      name: name,
      id: id
    }
  end
end
