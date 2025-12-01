defmodule WaxAPIREST.MixProject do
  use Mix.Project

  def project do
    [
      app: :wax_api_rest,
      description: "FIDO2 / WebAuthn server REST API library",
      version: "0.4.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [main: "readme", extras: ["README.md"]],
      package: package(),
      source_url: "https://github.com/tanguilp/wax_api_rest"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 1.4.7", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.39.0", only: :dev, runtime: false},
      {:plug, "~> 1.18.0"},
      {:wax_, "~> 0.7.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/wax_api_rest"}
    ]
  end
end
