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

  @default_pub_key_creds_params [
    {"public-key", -36},
    {"public-key", -35},
    {"public-key", -7}
  ]

  @derive Jason.Encoder

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
    attestation: "none"
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
    exclude_credentials =
      if user_info[:exclude_credentials] do
        Enum.map(
          user_info[:exclude_credentials],
          fn
            id when is_binary(id) ->
              ServerPublicKeyCredentialDescriptor.new(id)

            {id, transports} ->
              ServerPublicKeyCredentialDescriptor.new(id, transports)
          end
        )
      end

    attestation =
      Application.get_env(:wax_api_rest, :attestation_conveyance_preference)
      || opts[:attestation_conveyance_preference]
      || request.attestation
      || "none"

    %__MODULE__{
      rp: PublicKeyCredentialRpEntity.new(
        opts[:rp_name] || Application.get_env(:wax_api_rest, :rp_name) || challenge.rp_id,
        challenge.rp_id
      ),
      user: ServerPublicKeyCredentialUserEntity.new(
        user_info[:name] || request.username,
        user_info[:id],
        user_info[:display_name] || request.display_name
      ),
      challenge: Base.url_encode64(challenge.bytes),
      pubKeyCredParams: (
        opts[:pub_key_cred_params]
        || Application.get_env(:wax_api_rest, :pub_key_cred_params)
        || @default_pub_key_creds_params
        )
        |> Enum.map(fn {type, alg} -> PubKeyCredParams.new(type, alg) end),
      timeout: challenge.timeout,
      authenticatorSelection:
        if request.authenticatorSelection do
          %AuthenticatorSelectionCriteria{
            request.authenticatorSelection | userVerification: challenge.user_verified_required
          }
        end,
      extensions: nil,
      excludeCredentials: exclude_credentials,
      attestation: attestation
    }
  end
end
