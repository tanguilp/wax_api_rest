defmodule WaxAPIREST.Types.ServerPublicKeyCredentialCreationOptionsRequest do
  alias WaxAPIREST.Types.{
    AuthenticatorSelectionCriteria,
    AttestationConveyancePreference,
    Error
  }

  @enforce_keys [:username, :displayName]

  defstruct [
    :username,
    :displayName,
    :authenticatorSelection,
    :extensions,
    attestation: "none"
  ]

  @type t :: %__MODULE__{
    username: String.t(),
    displayName: String.t(),
    authenticatorSelection: AuthenticatorSelectionCriteria.t() | nil,
    extensions: %{required(String.t()) => any()},
    attestation: AttestationConveyancePreference.t() | nil
  }

  @spec new(map()) :: t() | no_return()
  def new(%{"username" => username, "displayName" => displayName} = request)
    when is_binary(username) and is_binary(displayName)
  do
    authenticatorSelection =
      if request["authenticatorSelection"] do
        AuthenticatorSelectionCriteria.new(request["authenticatorSelection"])
      end

    attestation =
      if request["attestation"] do
        AttestationConveyancePreference.new(request["attestation"])
      else
        "none"
      end

    %__MODULE__{
      username: username,
      displayName: displayName,
      authenticatorSelection: authenticatorSelection,
      extensions: request["extensions"] || %{},
      attestation: attestation
    }
  end

  def new(request) do
    if request["username"] == nil or not is_binary(request["username"]) do
      raise Error.MissingField, field: "username"
    end

    if request["displayName"] == nil or not is_binary(request["displayName"]) do
      raise Error.MissingField, field: "displayName"
    end
  end
end
