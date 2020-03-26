defmodule WaxAPIREST.Types.ServerPublicKeyCredentialGetOptionsRequest do
  alias  WaxAPIREST.Types.{
    Error,
    UserVerificationRequirement
  }

  @enforce_keys [:username]

  defstruct [
    :username,
    :extensions,
    userVerification: "preferred"
  ]

  @type t :: %__MODULE__{
    username: String.t(),
    extensions: %{required(String.t()) => any()},
    userVerification: UserVerificationRequirement.t() | nil
  }

  @spec new(map()) :: t()
  def new(%{"username" => username} = request) when is_binary(username) do
    userVerification =
      if request["userVerification"] do
        UserVerificationRequirement.new(request["userVerification"])
      else
        UserVerificationRequirement.new("preferred")
      end

    %__MODULE__{
      username: username,
      extensions: request["extensions"] || %{},
      userVerification: userVerification
    }
  end

  def new(_) do
    raise Error.MissingField, field: "username"
  end
end
