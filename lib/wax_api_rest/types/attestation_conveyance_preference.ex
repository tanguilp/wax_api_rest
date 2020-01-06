defmodule WaxAPIREST.Types.AttestationConveyancePreference do
  alias WaxAPIREST.Types.Error

  @typedoc """
  Must be one of:
  - `"none"`
  - `"indirect"`
  - `"direct"`
  """
  @type t :: String.t()

  @spec new(String.t()) :: t() | no_return()
  def new("none"), do: "none"
  def new("indirect"), do: "indirect"
  def new("direct"), do: "direct"
  def new(val), do: raise Error.InvalidField,
                    field: "attestation",
                    value: val,
                    accepted_value: ["none", "indirect", "direct"]
end
