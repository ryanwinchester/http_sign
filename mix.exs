defmodule HTTPSign.MixProject do
  use Mix.Project

  @description """
  HTTP Signature Verification in Elixir.
  """

  def project do
    [
      app: :http_sign,
      version: "0.1.1",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env),
      name: "HTTPSign",
      description: @description,
      package: package(),
      deps: deps(),
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/fixtures"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.0"},
      {:ex_doc, "~> 0.14", only: :dev},
    ]
  end

  defp package do
    [
      maintainers: ["Ryan Winchester"],
      licenses: ["MIT"],
      links: %{"Github" => "https://github.com/ryanwinchester/http_sign"},
    ]
end
end
