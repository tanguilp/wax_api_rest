defmodule WaxAPIREST.Types.ServerPublicKeyCredentialGetOptionsRequest do
  alias  WaxAPIREST.Types.{
    Error,
    UserVerificationRequirement
  }

  @enforce_keys [:username]

  defstruct [
    :username,
    userVerification: "preferred"
  ]

  @type t :: %__MODULE__{
    username: String.t(),
    userVerification: UserVerificationRequirement.t() | nil
  }

  @spec new(map()) :: t()
  def new(%{"username" => username} = request) when is_binary(username) do
    userVerification =
      if request["userVerification"] do
        UserVerificationRequirement.new(request["userVerification"])
      else
        "preferred"
      end

    %__MODULE__{
      username: username,
      userVerification: userVerification
    }
  end

  def new(_) do
    raise Error.MissingField, field: "username"
  end
end
