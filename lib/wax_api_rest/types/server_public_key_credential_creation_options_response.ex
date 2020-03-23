defmodule WaxAPIREST.Types.ServerPublicKeyCredentialCreationOptionsResponse do
  alias WaxAPIREST.Types.{
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PubKeyCredParams,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialDescriptor,
    ServerPublicKeyCredentialUserEntity
  }

  @default_pub_key_creds_params [-36, -35, -7]

  @enforce_keys [:rp, :user, :challenge, :pubKeyCredParams]

  defstruct [
    :rp,
    :user,
    :challenge,
    :pubKeyCredParams,
    :timeout,
    :authenticatorSelection,
    :extensions,
    excludeCredentials: [],
    attestation: "none",
    status: "ok",
    errorMessage: ""
  ]

  @type t :: %__MODULE__{
    rp: PublicKeyCredentialRpEntity.t(),
    user: ServerPublicKeyCredentialUserEntity.t(),
    challenge: String.t(),
    pubKeyCredParams: [PubKeyCredParams.t()],
    timeout: non_neg_integer() | nil,
    authenticatorSelection: AuthenticatorSelectionCriteria.t() | nil,
    extensions: map() | nil,
    excludeCredentials: [ServerPublicKeyCredentialDescriptor.t()] | nil,
    attestation: AttestationConveyancePreference.t() | nil
  }

  @spec new(
    ServerPublicKeyCredentialCreationOptionsRequest.t(),
    Wax.Challenge.t(),
    WaxAPIREST.Callback.user_info(),
    Keyword.t()
  ) :: t()
  def new(request, challenge, user_info, opts) do
    attestation =
      opts[:attestation_conveyance_preference]
      || Application.get_env(WaxAPIREST, :attestation_conveyance_preference)
      || request.attestation
      || "none"

    %__MODULE__{
      rp: PublicKeyCredentialRpEntity.new(
        opts[:rp_name] || Application.get_env(WaxAPIREST, :rp_name) || challenge.rp_id,
        challenge.rp_id
      ),
      user: ServerPublicKeyCredentialUserEntity.new(
        user_info[:name] || request.username,
        user_info[:id],
        user_info[:display_name] || request.displayName
      ),
      challenge: Base.url_encode64(challenge.bytes, padding: false),
      pubKeyCredParams: (
        opts[:pub_key_cred_params]
        || Application.get_env(WaxAPIREST, :pub_key_cred_params)
        || @default_pub_key_creds_params
        )
        |> Enum.map(fn
          alg when is_integer(alg) ->
            PubKeyCredParams.new(alg)

          {type, alg} ->
            PubKeyCredParams.new(type, alg)
        end),
      timeout: challenge.timeout,
      authenticatorSelection:
        if request.authenticatorSelection do
          %AuthenticatorSelectionCriteria{
            request.authenticatorSelection | userVerification: challenge.user_verified_required
          }
        end,
      extensions: nil,
      excludeCredentials: opts[:exclude_credentials] || [],
      attestation: attestation
    }
  end
end
