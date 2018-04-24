defmodule HTTPSign.Verifier do
  @moduledoc false

  import Plug.Conn

  alias Plug.Conn
  alias HTTPSign.{Crypto, Signature}

  # 2.5. Verifying a Signature
  # https://tools.ietf.org/id/draft-cavage-http-signatures-09.html#verify
  #
  # In order to verify a signature, a server MUST:
  #
  #   1. Use the received HTTP message, the `headers` value, and the Signature
  #      String Construction algorithm to recreate the signature string.
  #   2. The `algorithm`, `keyId`, and base 64 decoded `signature` listed in the
  #      signature parameters are then used to verify the authenticity of the
  #      digital signature.
  #
  # For example, assume that the `algorithm` value was "rsa-sha256". This would
  # signal to the application that the data associated with `keyId` is an RSA
  # Public Key (as defined in [RFC3447]), the signature string hashing function
  # is SHA-256, and the `signature` verification algorithm to use to verify the
  # signature is the one defined in [RFC3447], Section 8.2.2. The result of the
  # signature verification algorithm specified in [RFC3447] should result in a
  # successful verification unless the headers protected by the signature were
  # tampered with in transit.
  #
  # Appendix A. Security Considerations
  # https://tools.ietf.org/id/draft-cavage-http-signatures-09.html#rfc.appendix.A
  #
  # There are a number of security considerations to take into account when
  # implementing or utilizing this specification. A thorough security analysis of
  # this protocol, including its strengths and weaknesses, can be found in
  # [Security Considerations for HTTP Signatures]
  # (https://web-payments.org/specs/source/http-signatures-audit/).

  @doc """
  Verify the signature of the HTTP request.
  """
  @spec verify(Conn.t(), binary) :: {:ok, Conn.t()} | {:error, atom | binary}
  def verify(%Conn{} = conn, key) when is_binary(key) and byte_size(key) > 0 do
    with {:ok, header} <- get_signature_header(conn),
         {:ok, params} <- parse_signature_header(header),
         {:ok, signature_string} <- create_signature_string(conn, params) do
      if Crypto.verify(params.algorithm, signature_string, params.signature, key) do
        {:ok, conn}
      else
        {:error, :forbidden}
      end
    end
  end

  # We're looking for a header `Authorization: Signature [...]` or `Signature: [...]`
  # If for whatever reason, both headers are sent, we will prioritize the
  # `Authorization` header only because that is the order in which they are
  # listed in the draft spec.
  defp get_signature_header(conn) do
    case {get_req_header(conn, "authorization"), get_req_header(conn, "signature")} do
      # 3.1. Authorization Header
      # The client is expected to send an Authorization header (as defined in
      # RFC 7235, Section 4.1) where the "auth-scheme" is "Signature" and the
      # "auth-param" parameters meet the requirements listed in Section 2: The
      # Components of a Signature.
      {["Signature " <> sig_header], _} ->
        {:ok, sig_header}

      # 4.1. Signature Header
      # The sender is expected to transmit a header (as defined in RFC 7230,
      # Section 3.2) where the "field-name" is "Signature", and the "field-value"
      # contains one or more "auth-param"s (as defined in RFC 7235, Section 4.1)
      # where the "auth-param" parameters meet the requirements listed in Section 2:
      # The Components of a Signature.
      {_, [sig_header]} ->
        {:ok, sig_header}

      {_, _} ->
        {:error, "No signature header not found"}
    end
  end

  # 2.1. Signature Parameters
  # `keyId`:
  # REQUIRED. The `keyId` field is an opaque string that the server can use to
  # look up the component they need to validate the signature. It could be an
  # SSH key fingerprint, a URL to machine-readable key data, an LDAP DN, etc.
  # Management of keys and assignment of `keyId` is out of scope for this document.
  #
  # `algorithm`:
  # REQUIRED. The `algorithm` parameter is used to specify the digital signature
  # algorithm to use when generating the signature. Valid values for this
  # parameter can be found in the Signature Algorithms registry located at
  # http://www.iana.org/assignments/signature-algorithms and MUST NOT be marked
  # "deprecated".
  #
  # `headers`:
  # OPTIONAL. The `headers` parameter is used to specify the list of HTTP
  # headers included when generating the signature for the message. If
  # specified, it should be a lowercased, quoted list of HTTP header fields,
  # separated by a single space character. If not specified, implementations
  # MUST operate as if the field were specified with a single value, the `Date`
  # header, in the list of HTTP headers. Note that the list order is important,
  # and MUST be specified in the order the HTTP header field-value pairs are
  # concatenated together during signing.
  #
  # `signature`:
  # REQUIRED. The `signature` parameter is a base 64 encoded digital signature,
  # as described in RFC 4648, Section 4. The client uses the `algorithm` and
  # `headers` signature parameters to form a canonicalized `signing string`.
  # This `signing string` is then signed with the key associated with `keyId`
  # and the algorithm corresponding to `algorithm`. The `signature` parameter is
  # then set to the base 64 encoding of the signature.
  defp parse_signature_header(header) when is_binary(header) do
    with {:ok, key_id} <- get_header_param(header, "keyId"),
         {:ok, algorithm} <- get_header_param(header, "algorithm"),
         {:ok, headers} <- get_header_param(header, "headers"),
         {:ok, signature} <- get_header_param(header, "signature"),
         {:ok, signature} <- Base.decode64(signature) do
      {:ok,
        Signature.new(
          key_id,
          algorithm,
          signature,
          headers
        )
      }
    end
  end

  defp get_header_param(header, param) do
    case Regex.scan(~r/#{param}="([^"]+)"/, header, capture: :all_but_first) do
      [[value] | []] ->
        {:ok, value}

      [[_] | values] ->
        # 2.2. Ambiguous Parameters
        # If any of the parameters are erroneously duplicated in the associated
        # header field, then the last parameter defined MUST be used.
        [value] = List.last(values)
        {:ok, value}

      [] ->
        case param do
          "headers" -> {:ok, "date"}
          _ -> {:error, "Invalid header, [#{param}] was not specified"}
        end

      _ ->
        {:error, "Unable to parse header"}
    end
  end

  # 2.3. Signature String Construction
  # In order to generate the string that is signed with a key, the client MUST
  # use the values of each HTTP header field in the `headers` Signature
  # parameter, in the order they appear in the `headers` Signature parameter.
  # It is out of scope for this document to dictate what header fields an
  # application will want to enforce, but implementers SHOULD at minimum include
  # the request target and Date header fields.
  #
  # To include the HTTP request target in the signature calculation, use the
  # special `(request-target)` header field name.
  #
  # If value is not the last value then append an ASCII newline `\n`.
  defp create_signature_string(conn, %Signature{headers: headers})
      when is_list(headers) do
    signature_string = Enum.map(headers, &header_line(conn, &1)) |> Enum.join("\n")
    {:ok, signature_string}
  end

  # If the header field name is `(request-target)` then generate the header
  # field value by concatenating the lowercased :method, an ASCII space, and
  # the :path pseudo-headers (as specified in HTTP/2, Section 8.1.2.3).
  defp header_line(conn, "(request-target)") do
    method = String.downcase(conn.method)
    "(request-target): #{method} #{conn.request_path}?#{conn.query_string}"
  end

  # Create the header field string by concatenating the lowercased header field
  # name followed with an ASCII colon `:`, an ASCII space ` `, and the header
  # field value. Leading and trailing optional whitespace (OWS) in the header
  # field value MUST be omitted (as specified in RFC7230, Section 3.2.4). If
  # there are multiple instances of the same header field, all header field
  # values associated with the header field MUST be concatenated, separated by
  # a ASCII comma and an ASCII space `, `, and used in the order in which they
  # will appear in the transmitted HTTP message.
  defp header_line(conn, header) do
    value =
      conn
      |> get_req_header(header)
      |> Enum.map(&String.trim/1)
      |> Enum.join(", ")

    "#{header}: #{value}"
  end
end
