defmodule WaxAPIREST.Types.Error do
  defmodule MissingField do
    @enforce_keys [:field]
    defexception [:field]

    @type t :: %__MODULE__{
      field: String.t()
    }

    @impl true
    def message(%{field: field}) do
      "missing mandatory field `#{field}`"
    end
  end

  defmodule InvalidField do
    @enforce_keys [:field, :value, :accepted_value]
    defexception [:field, :value, :accepted_value]

    @type t :: %__MODULE__{
      field: String.t(),
      value: String.t(),
      accepted_value: [String.t()]
    }

    @impl true
    def message(%{field: field, value: value, accepted_value: accepted_value}) do
      "invalid field `#{field}` with value `#{value}`, must be one of: " <>
        Enum.join(accepted_value, ", ")
    end
  end
end
