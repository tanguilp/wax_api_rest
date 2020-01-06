defmodule WaxAPIREST.Types.AuthenticatorTransport do
  alias WaxAPIREST.Types.Error

  @typedoc """
  Must be one of:
  - `"usb"`
  - `"nfc"`
  - `"ble"`
  - `"internal"`
  - `"lightning"`
  """
  @type t :: String.t()

  @spec new(String.t()) :: t() | no_return()
  def new("usb"), do: "none"
  def new("nfc"), do: "indirect"
  def new("ble"), do: "direct"
  def new("internal"), do: "direct"
  def new("lightning"), do: "direct"
  def new(val), do: raise Error.InvalidField,
                    field: "transports",
                    value: val,
                    accepted_value: ["usb", "nfc", "ble", "internal", "lightning"]
end
