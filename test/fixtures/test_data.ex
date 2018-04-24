defmodule HTTPSign.TestData do
  @moduledoc """

  https://tools.ietf.org/id/draft-cavage-http-signatures-09.html#appendix-c

   # Appendix C. Test Values

   The following test data uses the following RSA 2048-bit keys, which we will
   refer to as `keyId=Test` in the following samples:

      -----BEGIN PUBLIC KEY-----
      MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
      6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
      Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
      oYi+1hqp1fIekaxsyQIDAQAB
      -----END PUBLIC KEY-----


      -----BEGIN RSA PRIVATE KEY-----
      MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
      NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
      UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
      AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
      QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
      kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
      f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
      412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
      mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
      kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
      gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
      G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
      7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
      -----END RSA PRIVATE KEY-----

  All examples use this request:

      POST /foo?param=value&pet=dog HTTP/1.1
      Host: example.com
      Date: Sun, 05 Jan 2014 21:31:40 GMT
      Content-Type: application/json
      Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
      Content-Length: 18

      {"hello": "world"}

  ## C.1. Default Test

  If a list of headers is not included, the date is the only header that is
  signed by default. The string to sign would be:

      date: Sun, 05 Jan 2014 21:31:40 GMT

  The Authorization header would be:

      Authorization: Signature keyId="Test",algorithm="rsa-sha256",
      signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz
      6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB
      6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="

  The Signature header would be:

      Signature: keyId="Test",algorithm="rsa-sha256",
      signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz
      6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB
      6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="

  ## C.2. Basic Test

  The minimum recommended data to sign is the (request-target), host, and date.
  In this case, the string to sign would be:

      (request-target): post /foo?param=value&pet=dog
      host: example.com
      date: Sun, 05 Jan 2014 21:31:40 GMT

  The Authorization header would be:

      Authorization: Signature keyId="Test",algorithm="rsa-sha256",
      headers="(request-target) host date", signature="qdx+H7PHHDZgy4
      y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn
      7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBs
      kLu6kd9Fswtemr3lgdDEmn04swr2Os0="

  ## C.3. All Headers Test

  A strong signature including all of the headers and a digest of the body of
  the HTTP request would result in the following signing string:

      (request-target): post /foo?param=value&pet=dog
      host: example.com
      date: Sun, 05 Jan 2014 21:31:40 GMT
      content-type: application/json
      digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
      content-length: 18

  The Authorization header would be:

      Authorization: Signature keyId="Test",algorithm="rsa-sha256",
      headers="(request-target) host date content-type digest content-length",
      signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs
      8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZF
      ukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="

  The Signature header would be:

    Signature: keyId="Test",algorithm="rsa-sha256",
    headers="(request-target) host date content-type digest content-length",
    signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs
    8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZF
    ukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="

  """

  def headers do
    [
      {"Host", "example.com"},
      {"Date", "Sun, 05 Jan 2014 21:31:40 GMT"},
      {"Content-Type", "application/json"},
      {"Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
      {"Content-Length", "18"},
    ]
  end

  def path do
    "/foo?param=value&pet=dog"
  end

  def body do
    ~s({"hello": "world"})
  end

  def pubkey do
    """
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
    6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
    Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
    oYi+1hqp1fIekaxsyQIDAQAB
    -----END PUBLIC KEY-----
    """
  end

  def privkey do
    """
    -----BEGIN RSA PRIVATE KEY-----
    MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
    NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
    UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
    AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
    QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
    kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
    f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
    412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
    mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
    kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
    gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
    G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
    7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
    -----END RSA PRIVATE KEY-----
    """
  end
end