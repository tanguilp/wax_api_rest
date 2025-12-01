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
  def register_key(conn, credential_id, authenticator_data, _attestation_result) do
    cookie = get_cookie(conn, "fido_test_suite")

    if cookie do
      cookie_hash = :crypto.hash(:sha256, cookie) |> Base.url_encode64()
      cose_key = authenticator_data.attested_credential_data.credential_public_key
      sign_count = authenticator_data.sign_count

      key_data = %{
        cose_key: cose_key,
        sign_count: sign_count
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
      case :ets.lookup(@table_name, cookie_hash) do
        entries when is_list(entries) ->
          case Enum.find(entries, fn {^cookie_hash, cred_id, _} -> cred_id == credential_id end) do
            {^cookie_hash, ^credential_id, key_data} ->
              updated_key_data = Map.put(key_data, :sign_count, authenticator_data.sign_count)
              # Delete old entry and insert updated one
              :ets.delete_object(@table_name, {cookie_hash, credential_id, key_data})
              :ets.insert(@table_name, {cookie_hash, credential_id, updated_key_data})

            _ ->
              :ok
          end

        [] ->
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
             "pubKeyCredParams" => _
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
             "challenge" => _
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
             "errorMessage" => _
           } = Jason.decode!(conn.resp_body)
  end
end
