defmodule WaxAPIREST.Types.UserVerificationRequirement do
  alias WaxAPIREST.Types.Error

  @typedoc """
  Must be one of:
  - `"required"`
  - `"preferred"`
  - `"discouraged"`
  """
  @type t :: String.t()

  @spec new(String.t()) :: t() | no_return()
  def new("required"), do: "required"
  def new("preferred"), do: "preferred"
  def new("discouraged"), do: "discouraged"
  def new(val), do: raise Error.InvalidField,
                    field: "userVerification",
                    value: val,
                    accepted_value: ["discouraged", "preferred", "required"]
end
