defmodule WaxAPIREST.Types.PubKeyCredParams do
  alias WaxAPIREST.Types.{
    Error,
    PublicKeyCredentialType
  }

  @derive Jason.Encoder

  @enforce_keys [:type, :alg]

  defstruct [
    :type,
    :alg
  ]

  @type t :: %__MODULE__{
    type: PublicKeyCredentialType.t(),
    alg: integer()
  }

  @spec new(PublicKeyCredentialType.t(), Wax.CoseKey.cose_alg()) :: t()
  def new(type, alg) do
    cose_algs = Wax.CoseKey.supported_algs() |> Map.keys()

    if alg in cose_algs do
      %__MODULE__{
        type: PublicKeyCredentialType.new(type),
        alg: alg
      }
    else
      raise Error.InvalidField,
              field: "alg",
              value: alg,
              accepted_value: cose_algs
    end
  end
end
