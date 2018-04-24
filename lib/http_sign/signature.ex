defmodule HTTPSign.Signature do
  @moduledoc false

  @enforce_keys [:key_id, :algorithm, :signature]
  defstruct [
    key_id: nil,
    algorithm: nil,
    headers: ["date"],
    signature: nil,
  ]

  @type t :: %HTTPSign.Signature{
    key_id: binary,
    algorithm: binary,
    headers: list,
    signature: binary
  }

  @default_headers ["date"]

  @doc """
  Create a new `%Signature{}` struct.

  ## Example

      iex> HTTPSign.Signature.new("rsa-key-1", "rsa-sha256", "abc123")
      %HTTPSign.Signature{
        algorithm: "rsa-sha256",
        headers: ["date"],
        key_id: "rsa-key-1",
        signature: "abc123"
      }

  """
  @spec new(binary, binary, binary, list) :: t
  def new(key_id, algo, signature, headers \\ @default_headers) do
    %HTTPSign.Signature{
      key_id: key_id,
      algorithm: algo,
      headers: default_headers(headers),
      signature: signature,
    }
  end

  defp default_headers(headers) when is_binary(headers) and byte_size(headers) > 0 do
    String.split(headers, " ")
  end

  defp default_headers(headers) when is_list(headers) and length(headers) > 0 do
    headers
  end

  defp default_headers(_), do: @default_headers
end
