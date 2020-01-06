defmodule WaxAPIREST.Types.AuthenticatorSelectionCriteria do
  alias WaxAPIREST.Types.{
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement
  }

  @derive Jason.Encoder

  defstruct [
    :authenticatorAttachment,
    :residentKey,
    requireResidentKey: false,
    userVerification: "preferred"
  ]

  @type t :: %__MODULE__{
    authenticatorAttachment: AuthenticatorAttachment.t() | nil,
    requireResidentKey: boolean(),
    residentKey: ResidentKeyRequirement.t() | nil,
    userVerification: UserVerificationRequirement.t() | nil
  }

  @spec new(map()) :: t()
  def new(data) do
    %__MODULE__{
      authenticatorAttachment: (if data["authenticatorAttachment"], do: AuthenticatorAttachment.new(data["authenticatorAttachment"])),
      requireResidentKey: data["requireResidentKey"],
      residentKey: (if data["residentKey"], do: ResidentKeyRequirement.new(data["residentKey"])),
      userVerification: (if data["userVerification"], do: UserVerificationRequirement.new(data["userVerification"]))
    }
  end
end
