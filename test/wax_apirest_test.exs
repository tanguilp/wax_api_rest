defmodule WaxAPIRESTTest do
  use ExUnit.Case
  doctest WaxAPIREST

  test "greets the world" do
    assert WaxAPIREST.hello() == :world
  end
end
