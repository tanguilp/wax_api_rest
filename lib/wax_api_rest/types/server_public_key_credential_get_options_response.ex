defmodule WaxAPIREST.Types.ServerPublicKeyCredentialGetOptionsResponse do
  alias WaxAPIREST.Types.{
    ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialGetOptionsRequest,
    UserVerificationRequirement
  }

  @enforce_keys [:challenge]

  defstruct [
    :challenge,
    :timeout,
    :rpId,
    :extensions,
    allowCredentials: [],
    userVerification: "preferred",
    status: "ok",
    errorMessage: ""
  ]

  @type t :: %__MODULE__{
    challenge: String.t(),
    timeout: non_neg_integer() | nil,
    rpId: String.t() | nil,
    extensions: %{optional(String.t()) => any()},
    allowCredentials: [ServerPublicKeyCredentialDescriptor.t()] | nil,
    userVerification: UserVerificationRequirement.t() | nil
  }

  @spec new(
    ServerPublicKeyCredentialGetOptionsRequest.t(),
    Wax.Challenge.t(),
    [ServerPublicKeyCredentialDescriptor.flat()],
    Keyword.t()
  ) :: t()
  def new(request, challenge, allow_credentials, _opts) do
    allow_credentials = Enum.map(
      allow_credentials,
      fn
        id when is_binary(id) ->
          ServerPublicKeyCredentialDescriptor.new(id)

        {id, transports} ->
          ServerPublicKeyCredentialDescriptor.new(id, transports)
      end
    )

    user_verification =
      if challenge.user_verified_required == true do
        UserVerificationRequirement.new("required")
      else
        request.userVerification
      end

    %__MODULE__{
      challenge: Base.url_encode64(challenge.bytes, padding: false),
      timeout: challenge.timeout,
      rpId: challenge.rp_id,
      extensions: request.extensions,
      allowCredentials: allow_credentials,
      userVerification: user_verification || "preferred"
    }
  end
end
