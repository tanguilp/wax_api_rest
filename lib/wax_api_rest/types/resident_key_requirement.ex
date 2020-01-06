defmodule WaxAPIREST.Types.ResidentKeyRequirement do
  alias WaxAPIREST.Types.Error

  @typedoc """
  Must be one of:
  - `"discouraged""`
  - `"preferred"`
  - `"required"`
  """
  @type t :: String.t()

  @spec new(String.t()) :: t() | no_return()
  def new("discouraged"), do: "discouraged"
  def new("preferred"), do: "preferred"
  def new("required"), do: "required"
  def new(val), do: raise Error.InvalidField,
                    field: "residentKey",
                    value: val,
                    accepted_value: ["discouraged", "preferred", "required"]
end
