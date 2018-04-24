defmodule HTTPSign do
  @moduledoc """
  HTTP signature verification based on IETF HTTP Signature Verification Draft spec.

  See:

    - https://tools.ietf.org/id/draft-cavage-http-signatures-09.html
    - https://web-payments.org/specs/source/http-signatures-audit/

  Supported algorithms are: `rsa-sha256`, `hmac-sha256`, and `ecdsa-sha256`.
  """

  # TODO: sign requests?

  @doc """
  Verify the signature of the HTTP request.
  """
  defdelegate verify(conn, key), to: HTTPSign.Verifier
end
