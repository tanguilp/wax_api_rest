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
    @enforce_keys [:field, :value]
    defexception [:field, :value, :accepted_value, :reason]

    @type t :: %__MODULE__{
      field: String.t(),
      value: String.t(),
      accepted_value: [String.t()],
      reason: String.t() | nil
    }

    @impl true
    def message(%{field: field, value: value, accepted_value: [_ | _] = accepted_value}) do
      "invalid field `#{field}` with value `#{value}`, must be one of: " <>
        Enum.join(accepted_value, ", ")
    end

    def message(%{field: field, value: value, reason: reason}) do
      "invalid field `#{field}` with value `#{value}` with reason: #{reason}"
    end
  end
end
