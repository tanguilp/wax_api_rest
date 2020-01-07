defmodule WaxAPIREST.PlugTest do
  use ExUnit.Case
  use Plug.Test

  defmodule AppRouter do
    use Plug.Router

    plug Plug.Session, store: :ets, key: "sid", table: :session

    plug(:match)
    plug(:dispatch)

    forward("/", to: WaxAPIREST.Plug)
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
        "id" => "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "rawId" => "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response" => %{
          "clientDataJSON" => "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
          "attestationObject" => "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
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
    WaxAPIREST.Callback.Test.setup_table()

    :ets.insert(
      WaxAPIREST.Callback.Test,
      {
        :crypto.hash(:sha256, "abcdef") |> Base.url_encode64(),
        "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        %{-3 => <<121, 21, 84, 106, 84, 48, 91, 21, 161, 78, 176, 199, 224, 86, 196, 226, 116, 207, 221, 200, 26, 202, 214, 78, 95, 112, 140, 236, 190, 183, 177, 223>>, -2 => <<195, 105, 55, 252, 13, 134, 94, 208, 83, 115, 8, 235, 190, 173, 107, 78, 247, 125, 65, 216, 252, 232, 41, 13, 39, 104, 231, 65, 200, 149, 172, 118>>, -1 => 1, 1 => 2, 3 => -7}
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
        "id" => "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "rawId" => "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response" => %{
          "authenticatorData" => "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
          "signature" => "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
          "userHandle" => "",
          "clientDataJSON" => "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
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
