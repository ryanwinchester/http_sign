defmodule HTTPSign.Crypto.RSA do
  @moduledoc false

  def sign(message, private_key) do
    :public_key.sign(message, :sha256, load(private_key))
  end

  def verify(message, signature, public_key) do
    :public_key.verify(message, :sha256, signature, load(public_key))
  end

  defp load(key) when is_binary(key) do
    key
    |> :public_key.pem_decode()
    |> Enum.at(0)
    |> :public_key.pem_entry_decode()
  end
end
