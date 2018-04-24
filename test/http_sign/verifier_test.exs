defmodule HTTPSign.VerifierTest do
  use ExUnit.Case
  use Plug.Test

  alias HTTPSign.TestData
  alias HTTPSign.Verifier

  test "default test authorization header" do
    conn =
      conn(:post, TestData.path(), TestData.body())
      |> put_req_header("content-type", "application/json")
      |> put_req_header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
      |> put_req_header("authorization", ~s(Signature keyId="Test",algorithm="rsa-sha256",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="))

    assert {:ok, _conn} = Verifier.verify(conn, TestData.pubkey())
  end

  test "default test signature header" do
    conn =
      conn(:post, TestData.path(), TestData.body())
      |> put_req_header("content-type", "application/json")
      |> put_req_header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
      |> put_req_header("signature", ~s(keyId="Test",algorithm="rsa-sha256",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="))

    assert {:ok, _conn} = Verifier.verify(conn, TestData.pubkey())
  end

  test "basic test authorization header" do
    conn =
      conn(:post, TestData.path(), TestData.body())
      |> put_req_header("content-type", "application/json")
      |> put_req_header("host", "example.com")
      |> put_req_header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
      |> put_req_header("authorization", ~s[Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date", signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="])

    assert {:ok, _conn} = Verifier.verify(conn, TestData.pubkey())
  end

  test "basic test signature header" do
    conn =
      conn(:post, TestData.path(), TestData.body())
      |> put_req_header("content-type", "application/json")
      |> put_req_header("host", "example.com")
      |> put_req_header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
      |> put_req_header("signature", ~s[keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date", signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0="])

    assert {:ok, _conn} = Verifier.verify(conn, TestData.pubkey())
  end

  test "all headers test authorization header" do
    conn =
      conn(:post, TestData.path(), TestData.body())
      |> put_req_header("content-type", "application/json")
      |> put_req_header("host", "example.com")
      |> put_req_header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
      |> put_req_header("digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
      |> put_req_header("content-length", "18")
      |> put_req_header("authorization", ~s[Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="])

    assert {:ok, _conn} = Verifier.verify(conn, TestData.pubkey())
  end

  test "all headers test signature header" do
    conn =
      conn(:post, TestData.path(), TestData.body())
      |> put_req_header("content-type", "application/json")
      |> put_req_header("host", "example.com")
      |> put_req_header("date", "Sun, 05 Jan 2014 21:31:40 GMT")
      |> put_req_header("digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
      |> put_req_header("content-length", "18")
      |> put_req_header("signature", ~s[keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="])

    assert {:ok, _conn} = Verifier.verify(conn, TestData.pubkey())
  end
end
