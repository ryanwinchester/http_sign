defmodule HTTPSigTest do
  use ExUnit.Case
  doctest HTTPSig

  test "greets the world" do
    assert HTTPSig.hello() == :world
  end
end
