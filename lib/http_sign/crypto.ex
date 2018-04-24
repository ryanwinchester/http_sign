defmodule HTTPSign.Crypto do
  @moduledoc """
  Crypto wrapper for signing and verifying messages.

  Supported algorithms are: `rsa-sha256`, `hmac-sha256`, and `ecdsa-sha256`.
  """

  alias HTTPSign.Crypto.{ECDSA, HMAC, RSA}

  @type algorithm :: :ecdsa | :hmac | :rsa

  @supported_algorithms ~w(rsa-sha256 hmac-sha256 ecdsa-sha256)

  @doc """
  Sign a message.
  """
  @spec sign(algorithm, binary, binary) :: {:ok, binary} | {:error, binary}
  def sign(algo, message, private_key)

  def sign(:ecdsa, message, private_key) do
    ECDSA.sign(message, private_key)
  end

  def sign(:hmac, message, private_key) do
    HMAC.sign(message, private_key)
  end

  def sign(:rsa, message, private_key) do
    RSA.sign(message, private_key)
  end

  @doc """
  Verify a signed message.
  """
  @spec verify(algorithm, binary, binary, binary) :: {:ok, binary} | {:error, binary}
  def verify(algo, message, signature, public_key)

  def verify(algo, message, signature, public_key)
      when is_binary(algo) and algo in @supported_algorithms do
    verify(algo_to_atom(algo), message, signature, public_key)
  end

  def verify(algo, _message, _signature, _public_key) when is_binary(algo) do
    {:error, "Unsupported algorithm, #{algo}"}
  end

  def verify(:ecdsa, message, signature, public_key) do
    ECDSA.verify(message, signature, public_key)
  end

  def verify(:hmac, message, signature, public_key) do
    HMAC.verify(message, signature, public_key)
  end

  def verify(:rsa, message, signature, public_key) do
    RSA.verify(message, signature, public_key)
  end

  defp algo_to_atom("ecdsa-sha256"), do: :ecdsa
  defp algo_to_atom("hmac-sha256"), do: :hmac
  defp algo_to_atom("rsa-sha256"), do: :rsa
end
