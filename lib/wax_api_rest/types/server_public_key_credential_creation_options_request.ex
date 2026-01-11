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

  # Maximum lengths for input validation (security: prevent DoS via large inputs)
  @max_username_length 256
  @max_display_name_length 256

  @spec new(map()) :: t() | no_return()
  def new(%{"username" => username, "displayName" => displayName} = request)
    when is_binary(username) and is_binary(displayName)
  do
    # Validate input sizes to prevent DoS attacks
    if byte_size(username) > @max_username_length do
      raise Error.InvalidField,
        field: "username",
        value: username,
        reason: "exceeds maximum length of #{@max_username_length} bytes"
    end

    if byte_size(displayName) > @max_display_name_length do
      raise Error.InvalidField,
        field: "displayName",
        value: displayName,
        reason: "exceeds maximum length of #{@max_display_name_length} bytes"
    end

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
