defmodule WaxAPIREST.Callback.Test do
  @moduledoc """
  Implementation of `WaxAPIREST.Callback` for testing purpose

  **DO NOT USE IT** in production, as it doesn't follow best practices.

  This implementation:
  - returns the hashed FIDO2 test suite cookie value as the user id
  - stores the challenge in the `t:Plug.Conn.t/0` object
  - creates an ETS table on the fly, whose heir is the root supervisor
  """

  @cookie_name "toto"

  @behaviour WaxAPIREST.Callback

  @impl true
  def user_info(conn, _request) do
    %{
      id: user_id_from_cookie(conn)
    }
  end

  @impl true
  def put_challenge(conn, challenge) do
    Plug.Conn.put_session(conn, :wax_api_rest_challenge, challenge)
  end

  @impl true
  def get_challenge(conn) do
    Plug.Conn.get_session(conn, :wax_api_rest_challenge) || raise "Challenge not found in session"
  end

  @impl true
  def register_key(conn, key_id, authenticator_data, _attestation_result) do
    setup_table()

    user_id = user_id_from_cookie(conn)

    true = :ets.insert(__MODULE__, {
      user_id,
      key_id,
      authenticator_data.attested_credential_data.credential_public_key
    })

    conn
  end

  @impl true
  def user_keys(conn, _request) do
    setup_table()

    user_id = user_id_from_cookie(conn)

    :ets.lookup(__MODULE__, user_id)
    |> Enum.reduce(
      %{},
      fn {^user_id, key_id, cose_key}, acc -> Map.put(acc, key_id, cose_key) end
    )
  end

  @impl true
  def on_authentication_success(conn, _authenticator_metadata) do
    conn
  end

  defp setup_table() do
    case :ets.info(__MODULE__) do
      :undefined ->
        :ets.new(__MODULE__, [:named_table, :bag, :public, {:heir, root_pid(), []}])
        :ets.give_away(__MODULE__, root_pid(), [])

      _ ->
        :ok
    end
  end

  defp session_cookie_value(conn) do
    Enum.find_value(
      conn.req_headers,
      fn 
        {"cookie", value} ->
          value
          |> String.split(";")
          |> Enum.map(&String.trim/1)
          |> Enum.find_value(
            fn cookie ->
              case String.split(cookie, "=") do
                [@cookie_name, cookie_value] ->
                  cookie_value

                _ ->
                  false
              end
            end
          )

        _ ->
          false
      end
    )
  end

  defp user_id_from_cookie(conn) do
    :crypto.hash(:sha256, session_cookie_value(conn))
    |> Base.url_encode64()
  end

  defp root_pid() do
    :erlang.list_to_pid('<0.0.0>')
  end
end
