defmodule WaxAPIREST.Types.PublicKeyCredentialType do
  alias WaxAPIREST.Types.Error

  @typedoc """
  Must be one of:
  - `"public-type"`
  """
  @type t :: String.t()

  @spec new(String.t()) :: t() | no_return()
  def new("public-key"), do: "public-key"
  def new(val), do: raise Error.InvalidField,
                    field: "type",
                    value: val,
                    accepted_value: ["public-key"]
end
