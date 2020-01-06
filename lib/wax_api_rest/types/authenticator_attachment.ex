defmodule WaxAPIREST.Types.AuthenticatorAttachment do
  alias WaxAPIREST.Types.Error

  @typedoc """
  Must be either `"platform"` or `"cross-platform"`
  """
  @type t :: String.t()

  @spec new(String.t()) :: t() | no_return()
  def new("platform"), do: "platform"
  def new("cross-platform"), do: "cross-platform"
  def new(val), do: raise Error.InvalidField,
                          field: "authenticatorAttachment",
                          value: val,
                          accepted_value: ["platform", "cross-platform"]
end
