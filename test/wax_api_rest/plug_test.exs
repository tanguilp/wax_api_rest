defmodule WaxAPIREST.Callback.Test do
  @moduledoc """
  Test callback module that implements WaxAPIREST.Callback behaviour using ETS tables
  """
  @behaviour WaxAPIREST.Callback

  @table_name __MODULE__

  def setup_table do
    # Use :bag to allow multiple entries with the same key (cookie_hash)
    :ets.new(@table_name, [:named_table, :public, :bag])
  end

  @impl WaxAPIREST.Callback
  def user_info(conn) do
    # Extract username from request body params
    username = get_in(conn.body_params, ["username"]) || "testuser@example.com"

    %{
      id: :crypto.hash(:sha256, username) |> Base.url_encode64(),
      name: username,
      display_name: get_in(conn.body_params, ["displayName"]) || username
    }
  end

  @impl WaxAPIREST.Callback
  def user_keys(conn) do
    cookie = get_cookie(conn, "fido_test_suite")

    if cookie do
      cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()

      # With :bag table, lookup returns all entries with matching key (cookie_hash)
      # The test inserts as {cookie_hash, credential_id, cose_key_map}
      :ets.lookup(@table_name, cookie_hash)
      |> Enum.map(fn {^cookie_hash, credential_id, key_data} ->
        # Convert COSE key map to proper key_data format if needed
        key_data_map =
          if is_map(key_data) and Map.has_key?(key_data, :cose_key) do
            key_data
          else
            # If it's a raw COSE key map (from test setup), wrap it
            %{cose_key: key_data}
          end

        {credential_id, key_data_map}
      end)
    else
      []
    end
  end

  @impl WaxAPIREST.Callback
  def put_challenge(conn, challenge) do
    cookie = get_cookie(conn, "fido_test_suite")

    if cookie do
      cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()
      challenge_binary = :erlang.term_to_binary(challenge)
      # Store challenge with timestamp for expiration checking (5 minute timeout)
      timestamp = System.system_time(:second)
      :ets.insert(@table_name, {cookie_hash <> "_challenge", challenge_binary, timestamp})
    end

    conn
  end

  @impl WaxAPIREST.Callback
  def get_challenge(conn) do
    cookie = get_cookie(conn, "fido_test_suite")

    cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()

    case :ets.lookup(@table_name, cookie_hash <> "_challenge") do
      [{_, challenge_binary, timestamp}] ->
        # Check challenge expiration (5 minute timeout)
        current_time = System.system_time(:second)

        if current_time - timestamp > 300 do
          raise "challenge expired"
        end

        :erlang.binary_to_term(challenge_binary)

      [] ->
        raise "challenge not found"
    end
  end

  @impl WaxAPIREST.Callback
  def invalidate_challenge(conn) do
    cookie = get_cookie(conn, "fido_test_suite")

    if cookie do
      cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()
      :ets.delete(@table_name, cookie_hash <> "_challenge")
    end

    conn
  end

  @impl WaxAPIREST.Callback
  def register_key(conn, credential_id, authenticator_data, _attestation_result, transports) do
    cookie = get_cookie(conn, "fido_test_suite")

    if cookie do
      cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()
      cose_key = authenticator_data.attested_credential_data.credential_public_key
      sign_count = authenticator_data.sign_count

      key_data = %{
        cose_key: cose_key,
        sign_count: sign_count,
        transports: transports
      }

      # Store as 3-tuple to match test format: {cookie_hash, credential_id, key_data}
      :ets.insert(@table_name, {cookie_hash, credential_id, key_data})
    end

    conn
  end

  @impl WaxAPIREST.Callback
  def on_authentication_success(conn, credential_id, authenticator_data) do
    cookie = get_cookie(conn, "fido_test_suite")

    if cookie do
      cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()

      # Find the entry matching this credential_id
      entries = :ets.lookup(@table_name, cookie_hash)

      case Enum.find(entries, fn {^cookie_hash, cred_id, _} -> cred_id == credential_id end) do
        {^cookie_hash, ^credential_id, key_data} ->
          updated_key_data = Map.put(key_data, :sign_count, authenticator_data.sign_count)
          # Delete old entry and insert updated one
          :ets.delete_object(@table_name, {cookie_hash, credential_id, key_data})
          :ets.insert(@table_name, {cookie_hash, credential_id, updated_key_data})

        _ ->
          :ok
      end
    end

    conn
  end

  defp get_cookie(conn, name) do
    conn
    |> Plug.Conn.fetch_cookies()
    |> Map.get(:cookies)
    |> Map.get(name)
  end
end

defmodule WaxAPIREST.PlugTest do
  use ExUnit.Case
  import Plug.Conn
  import Plug.Test

  defmodule AppRouter do
    use Plug.Router

    plug(Plug.Session, store: :ets, key: "sid", table: :session)

    plug(:match)
    plug(:dispatch)

    forward("/", to: WaxAPIREST.Plug, callback_module: WaxAPIREST.Callback.Test)
  end

  defmodule AppRouterTimeout do
    use Plug.Router

    plug(:match)
    plug(:dispatch)

    forward("/",
      to: WaxAPIREST.Plug,
      callback_module: WaxAPIREST.Callback.Test,
      timeout: 60
    )
  end

  defmodule AppRouterAuthenticatorSelectionMap do
    use Plug.Router

    plug(:match)
    plug(:dispatch)

    forward("/",
      to: WaxAPIREST.Plug,
      callback_module: WaxAPIREST.Callback.Test,
      authenticator_selection: %{
        "residentKey" => "required",
        "requireResidentKey" => true,
        "userVerification" => "required"
      }
    )
  end

  defmodule AppRouterAuthenticatorSelectionStruct do
    use Plug.Router

    plug(:match)
    plug(:dispatch)

    forward("/",
      to: WaxAPIREST.Plug,
      callback_module: WaxAPIREST.Callback.Test,
      authenticator_selection: %WaxAPIREST.Types.AuthenticatorSelectionCriteria{
        residentKey: "required",
        userVerification: "required"
      }
    )
  end

  defmodule AppRouterUserVerification do
    use Plug.Router

    plug(:match)
    plug(:dispatch)

    forward("/",
      to: WaxAPIREST.Plug,
      callback_module: WaxAPIREST.Callback.Test,
      user_verification: "required"
    )
  end

  defmodule AppRouterInvalidUserVerification do
    use Plug.Router

    plug(:match)
    plug(:dispatch)

    forward("/",
      to: WaxAPIREST.Plug,
      callback_module: WaxAPIREST.Callback.Test,
      user_verification: "Required"
    )
  end

  setup do
    WaxAPIREST.Callback.Test.setup_table()
    :ok
  end

  test "attestation" do
    request = %{
      "username" => "johndoe@example.com",
      "displayName" => "John Doe",
      "authenticatorSelection" => %{
        "residentKey" => false,
        "authenticatorAttachment" => "cross-platform",
        "userVerification" => "preferred"
      },
      "attestation" => "direct"
    }

    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "ok",
             "errorMessage" => "",
             "rp" => _,
             "user" => _,
             "challenge" => _,
             "pubKeyCredParams" => _,
             # the default Wax challenge timeout (120 seconds) in milliseconds
             "timeout" => 120_000
           } = Jason.decode!(conn.resp_body)

    request =
      %{
        "id" =>
          "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "rawId" =>
          "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response" => %{
          "clientDataJSON" =>
            "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
          "attestationObject" =>
            "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "type" => "public-key"
      }

    conn =
      conn(:post, "/attestation/result", request)
      |> recycle_cookies(conn)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "failed",
             "errorMessage" => _
           } = Jason.decode!(conn.resp_body)
  end

  test "configured authenticator selection (map) overrides the request's" do
    request = %{
      "username" => "johndoe@example.com",
      "displayName" => "John Doe",
      "authenticatorSelection" => %{
        "residentKey" => "discouraged",
        "requireResidentKey" => false,
        "userVerification" => "discouraged"
      }
    }

    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterAuthenticatorSelectionMap.call([])

    assert %{
             "status" => "ok",
             "authenticatorSelection" => %{
               "residentKey" => "required",
               "requireResidentKey" => true,
               "userVerification" => "required"
             }
           } = Jason.decode!(conn.resp_body)
  end

  test "configured authenticator selection (struct) overrides the request's" do
    request = %{
      "username" => "johndoe@example.com",
      "displayName" => "John Doe",
      "authenticatorSelection" => %{"residentKey" => "discouraged"}
    }

    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterAuthenticatorSelectionStruct.call([])

    assert %{
             "status" => "ok",
             "authenticatorSelection" => %{
               "residentKey" => "required",
               "userVerification" => "required"
             }
           } = Jason.decode!(conn.resp_body)
  end

  test "configured authenticator selection from the application environment" do
    Application.put_env(WaxAPIREST, :authenticator_selection, %{"residentKey" => "required"})
    on_exit(fn -> Application.delete_env(WaxAPIREST, :authenticator_selection) end)

    request = %{
      "username" => "johndoe@example.com",
      "displayName" => "John Doe",
      "authenticatorSelection" => %{"residentKey" => "discouraged"}
    }

    # with a router that doesn't set the option, the application environment applies
    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "ok",
             "authenticatorSelection" => %{"residentKey" => "required"} = selection
           } = Jason.decode!(conn.resp_body)

    refute Map.has_key?(selection, "userVerification")

    # the plug option takes precedence over the application environment
    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterAuthenticatorSelectionMap.call([])

    assert %{
             "status" => "ok",
             "authenticatorSelection" => %{
               "residentKey" => "required",
               "userVerification" => "required"
             }
           } = Jason.decode!(conn.resp_body)
  end

  test "configured userVerification is set on the registration challenge" do
    request = %{"username" => "johndoe@example.com", "displayName" => "John Doe"}

    conn(:post, "/attestation/options", request)
    |> put_req_cookie("fido_test_suite", "abcdef")
    |> put_resp_content_type("application/json")
    |> AppRouterAuthenticatorSelectionMap.call([])

    assert %Wax.Challenge{user_verification: "required"} = stored_challenge("abcdef")
  end

  test "configured userVerification rejects an attestation result without the UV flag" do
    request = %{"username" => "johndoe@example.com", "displayName" => "John Doe"}

    conn(:post, "/attestation/options", request)
    |> put_req_cookie("fido_test_suite", "abcdef")
    |> put_resp_content_type("application/json")
    |> AppRouterAuthenticatorSelectionMap.call([])

    challenge = stored_challenge("abcdef")
    assert challenge.user_verification == "required"

    # re-target the plug-created challenge at the U2F test vector, whose
    # authenticator data has the UV flag unset
    %{
      challenge
      | bytes: Base.url_decode64!("NxyZopwVKbFl7EnnMae_5Fnir7QJ7QWp1UFUKjFHlfk", padding: false),
        origin: "http://localhost:3000",
        rp_id: "localhost",
        attestation: "direct",
        verify_trust_root: false
    }
    |> replace_stored_challenge("abcdef")

    conn =
      conn(:post, "/attestation/result", attestation_result_request())
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterAuthenticatorSelectionMap.call([])

    assert conn.status == 400

    # the raw Wax error message is not leaked to the client
    assert %{"status" => "failed", "errorMessage" => "registration failed"} =
             Jason.decode!(conn.resp_body)

    # no key has been registered
    cookie_hash = :crypto.hash(:sha256, "abcdef") |> Base.url_encode64()
    assert :ets.lookup(WaxAPIREST.Callback.Test, cookie_hash) == []
  end

  test "the request's authenticator selection is used when none is configured" do
    request = %{
      "username" => "johndoe@example.com",
      "displayName" => "John Doe",
      "authenticatorSelection" => %{"residentKey" => "preferred"}
    }

    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "ok",
             "authenticatorSelection" => %{"residentKey" => "preferred"}
           } = Jason.decode!(conn.resp_body)
  end

  test "attestation result passes client transports to the callback" do
    forged_registration_challenge() |> store_challenge("abcdef")

    request =
      attestation_result_request()
      |> Map.put("transports", ["usb", "internal", "carrier-pigeon"])

    conn =
      conn(:post, "/attestation/result", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{"status" => "ok", "errorMessage" => ""} = Jason.decode!(conn.resp_body)

    cookie_hash = :crypto.hash(:sha256, "abcdef") |> Base.url_encode64()

    assert [{^cookie_hash, _credential_id, key_data}] =
             :ets.lookup(WaxAPIREST.Callback.Test, cookie_hash)

    # invalid transport values are silently dropped
    assert key_data.transports == ["usb", "internal"]
  end

  test "attestation result prefers transports nested in the response object" do
    forged_registration_challenge() |> store_challenge("abcdef")

    request =
      attestation_result_request()
      |> Map.put("transports", ["nfc"])
      |> Map.update!("response", &Map.put(&1, "transports", ["usb", "hybrid"]))

    conn =
      conn(:post, "/attestation/result", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{"status" => "ok", "errorMessage" => ""} = Jason.decode!(conn.resp_body)

    cookie_hash = :crypto.hash(:sha256, "abcdef") |> Base.url_encode64()

    assert [{^cookie_hash, _credential_id, key_data}] =
             :ets.lookup(WaxAPIREST.Callback.Test, cookie_hash)

    assert key_data.transports == ["usb", "hybrid"]
  end

  test "attestation result passes an empty transport list when the client sends none" do
    forged_registration_challenge() |> store_challenge("abcdef")

    conn =
      conn(:post, "/attestation/result", attestation_result_request())
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{"status" => "ok", "errorMessage" => ""} = Jason.decode!(conn.resp_body)

    cookie_hash = :crypto.hash(:sha256, "abcdef") |> Base.url_encode64()

    assert [{^cookie_hash, _credential_id, key_data}] =
             :ets.lookup(WaxAPIREST.Callback.Test, cookie_hash)

    assert key_data.transports == []
  end

  test "attestation options convert a non-default challenge timeout to milliseconds" do
    request = %{"username" => "johndoe@example.com", "displayName" => "John Doe"}

    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterTimeout.call([])

    assert %{"status" => "ok", "timeout" => 60_000} = Jason.decode!(conn.resp_body)
  end

  test "assertion options convert a non-default challenge timeout to milliseconds" do
    conn =
      conn(:post, "/assertion/options", %{"username" => "johndoe@example.com"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterTimeout.call([])

    assert %{"status" => "ok", "timeout" => 60_000} = Jason.decode!(conn.resp_body)
  end

  test "assertion options include stored credential transports" do
    :ets.insert(
      WaxAPIREST.Callback.Test,
      {
        :crypto.hash(:sha256, "abcdef") |> Base.url_encode64(),
        "credential-with-transports",
        %{cose_key: %{}, transports: ["internal", "hybrid"]}
      }
    )

    conn =
      conn(:post, "/assertion/options", %{"username" => "johndoe@example.com"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "ok",
             "allowCredentials" => [descriptor]
           } = Jason.decode!(conn.resp_body)

    assert descriptor["id"] == "credential-with-transports"
    assert descriptor["transports"] == ["internal", "hybrid"]
  end

  test "assertion options omit transports when none are stored" do
    cookie_hash = :crypto.hash(:sha256, "abcdef") |> Base.url_encode64()

    :ets.insert(
      WaxAPIREST.Callback.Test,
      {cookie_hash, "credential-without-transports", %{cose_key: %{}}}
    )

    :ets.insert(
      WaxAPIREST.Callback.Test,
      {cookie_hash, "credential-with-empty-transports", %{cose_key: %{}, transports: []}}
    )

    conn =
      conn(:post, "/assertion/options", %{"username" => "johndoe@example.com"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "ok",
             "allowCredentials" => [_, _] = descriptors
           } = Jason.decode!(conn.resp_body)

    for descriptor <- descriptors do
      refute Map.has_key?(descriptor, "transports")
    end
  end

  test "assertion options accept a request without username" do
    :ets.insert(
      WaxAPIREST.Callback.Test,
      {
        :crypto.hash(:sha256, "abcdef") |> Base.url_encode64(),
        "some-credential",
        %{cose_key: %{}}
      }
    )

    conn =
      conn(:post, "/assertion/options", %{"userVerification" => "required"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "ok",
             "errorMessage" => "",
             "challenge" => _,
             "userVerification" => "required",
             # credential selection is entirely up to the user_keys/1 callback
             "allowCredentials" => [%{"id" => "some-credential"}]
           } = Jason.decode!(conn.resp_body)
  end

  test "configured user_verification overrides the request's on assertion options" do
    conn =
      conn(:post, "/assertion/options", %{"userVerification" => "discouraged"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterUserVerification.call([])

    # the enforced value is advertised in the response...
    assert %{"status" => "ok", "userVerification" => "required"} =
             Jason.decode!(conn.resp_body)

    # ...and set on the challenge, so Wax.authenticate/6 enforces it
    assert %Wax.Challenge{user_verification: "required"} = stored_challenge("abcdef")
  end

  test "configured user_verification from the application environment overrides the request's" do
    Application.put_env(WaxAPIREST, :user_verification, "required")
    on_exit(fn -> Application.delete_env(WaxAPIREST, :user_verification) end)

    conn =
      conn(:post, "/assertion/options", %{"userVerification" => "discouraged"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{"status" => "ok", "userVerification" => "required"} =
             Jason.decode!(conn.resp_body)

    assert %Wax.Challenge{user_verification: "required"} = stored_challenge("abcdef")
  end

  test "the user_verification plug option does not apply to the registration ceremony" do
    request = %{"username" => "johndoe@example.com", "displayName" => "John Doe"}

    conn =
      conn(:post, "/attestation/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterUserVerification.call([])

    assert conn.status == 200

    # the registration challenge keeps Wax's default, not the configured "required"
    assert %Wax.Challenge{user_verification: "preferred"} = stored_challenge("abcdef")

    # the option is not echoed as authenticator selection criteria either
    refute Map.has_key?(Jason.decode!(conn.resp_body), "authenticatorSelection")
  end

  test "an invalid configured user_verification is rejected" do
    conn =
      conn(:post, "/assertion/options", %{"username" => "johndoe@example.com"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")

    # `Plug.ErrorHandler` sends the sanitized error response, then re-raises
    assert_raise Plug.Conn.WrapperError, ~r/invalid field `userVerification`/, fn ->
      AppRouterInvalidUserVerification.call(conn, [])
    end

    assert {400, _headers, body} = sent_resp(conn)

    assert %{
             "status" => "failed",
             "errorMessage" =>
               "invalid field `userVerification`, must be one of: discouraged, preferred, required"
           } = Jason.decode!(body)
  end

  test "the plug option takes precedence over the application environment" do
    Application.put_env(WaxAPIREST, :user_verification, "discouraged")
    on_exit(fn -> Application.delete_env(WaxAPIREST, :user_verification) end)

    conn =
      conn(:post, "/assertion/options", %{"username" => "johndoe@example.com"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouterUserVerification.call([])

    assert %{"status" => "ok", "userVerification" => "required"} =
             Jason.decode!(conn.resp_body)

    assert %Wax.Challenge{user_verification: "required"} = stored_challenge("abcdef")
  end

  test "the request's userVerification is used when none is configured" do
    conn =
      conn(:post, "/assertion/options", %{"userVerification" => "discouraged"})
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{"status" => "ok", "userVerification" => "discouraged"} =
             Jason.decode!(conn.resp_body)

    assert %Wax.Challenge{user_verification: "discouraged"} = stored_challenge("abcdef")
  end

  test "authentication" do
    :ets.insert(
      WaxAPIREST.Callback.Test,
      {
        :crypto.hash(:sha256, "abcdef") |> Base.url_encode64(),
        "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        %{
          -3 =>
            <<121, 21, 84, 106, 84, 48, 91, 21, 161, 78, 176, 199, 224, 86, 196, 226, 116, 207,
              221, 200, 26, 202, 214, 78, 95, 112, 140, 236, 190, 183, 177, 223>>,
          -2 =>
            <<195, 105, 55, 252, 13, 134, 94, 208, 83, 115, 8, 235, 190, 173, 107, 78, 247, 125,
              65, 216, 252, 232, 41, 13, 39, 104, 231, 65, 200, 149, 172, 118>>,
          -1 => 1,
          1 => 2,
          3 => -7
        }
      }
    )

    request = %{
      "username" => "johndoe@example.com",
      "userVerification" => "required"
    }

    conn =
      conn(:post, "/assertion/options", request)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "ok",
             "errorMessage" => "",
             "challenge" => _,
             # the default Wax challenge timeout (120 seconds) in milliseconds
             "timeout" => 120_000
           } = Jason.decode!(conn.resp_body)

    request =
      %{
        "id" =>
          "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "rawId" =>
          "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response" => %{
          "authenticatorData" => "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
          "signature" =>
            "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
          "userHandle" => "",
          "clientDataJSON" =>
            "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "type" => "public-key"
      }

    conn =
      conn(:post, "/assertion/result", request)
      |> recycle_cookies(conn)
      |> put_req_cookie("fido_test_suite", "abcdef")
      |> put_resp_content_type("application/json")
      |> AppRouter.call([])

    assert %{
             "status" => "failed",
             "errorMessage" => "authentication failed"
           } = Jason.decode!(conn.resp_body)
  end

  # A genuine FIDO U2F registration test vector. The challenge contained in its
  # clientDataJSON is "NxyZopwVKbFl7EnnMae_5Fnir7QJ7QWp1UFUKjFHlfk" and its
  # origin is "http://localhost:3000".
  defp attestation_result_request do
    %{
      "id" =>
        "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
      "rawId" =>
        "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
      "response" => %{
        "clientDataJSON" =>
          "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
        "attestationObject" =>
          "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
      },
      "type" => "public-key"
    }
  end

  # Builds a registration challenge whose bytes match the challenge of the
  # attestation_result_request/0 test vector, so that Wax.register/3 succeeds
  defp forged_registration_challenge do
    challenge =
      Wax.new_registration_challenge(
        origin: "http://localhost:3000",
        rp_id: "localhost",
        attestation: "direct",
        verify_trust_root: false
      )

    %{
      challenge
      | bytes: Base.url_decode64!("NxyZopwVKbFl7EnnMae_5Fnir7QJ7QWp1UFUKjFHlfk", padding: false)
    }
  end

  defp store_challenge(challenge, cookie) do
    cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()

    :ets.insert(
      WaxAPIREST.Callback.Test,
      {cookie_hash <> "_challenge", :erlang.term_to_binary(challenge),
       System.system_time(:second)}
    )
  end

  defp stored_challenge(cookie) do
    cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()

    [{_, challenge_binary, _timestamp}] =
      :ets.lookup(WaxAPIREST.Callback.Test, cookie_hash <> "_challenge")

    :erlang.binary_to_term(challenge_binary)
  end

  defp replace_stored_challenge(challenge, cookie) do
    cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()

    :ets.delete(WaxAPIREST.Callback.Test, cookie_hash <> "_challenge")
    store_challenge(challenge, cookie)
  end
end
