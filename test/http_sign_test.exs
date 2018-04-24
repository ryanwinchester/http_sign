defmodule HTTPSignTest do
  use ExUnit.Case
  use Plug.Test

  alias HTTPSign.TestData

  test "all headers test authorization header" do
    conn =
      conn(:post, TestData.path(), TestData.body())
      |> put_req_header("content-type", "application/json")
      |> put_req_header("host", "example.com")
      |> put_req_header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
      |> put_req_header("digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
      |> put_req_header("content-length", "18")
      |> put_req_header("authorization", ~s[Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="])

    assert {:ok, _conn} = HTTPSign.verify(conn, TestData.pubkey())
  end
end
