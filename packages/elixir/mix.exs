defmodule NebulaToken.MixProject do
  use Mix.Project

  # The only constant-time comparison in the package is :crypto.hash_equals/2
  # ([N-31]), which Erlang/OTP added in 25. It backs BOTH the verifier proof and
  # the sender binding, so on an older OTP `issue/3` works and every `refresh/3`
  # raises UndefinedFunctionError — a defect that surfaces in production rather
  # than at build time.
  #
  # `elixir: "~> 1.18"` already implies OTP 25+ (Elixir 1.18 supports OTP 25-27),
  # but Mix does not enforce an OTP floor on its own, and nothing stops a
  # consumer from vendoring the sources. The explicit check below turns the
  # runtime failure into a build failure.
  #
  # This floor tracks the code, not the support matrix, and the two are allowed
  # to diverge: raising the *Elixir* floor never raises this number, because 25
  # is simply where the function appears. .github/runtime-matrix.json therefore
  # pairs its lowest Elixir leg with OTP 25 on purpose — testing only newer OTPs
  # would leave this guard unexercised.
  @minimum_otp 25

  if String.to_integer(System.otp_release()) < @minimum_otp do
    Mix.raise(
      "nebula_token requires Erlang/OTP #{@minimum_otp} or later " <>
        "(:crypto.hash_equals/2, SPECIFICATION.md [N-31]); this is OTP #{System.otp_release()}"
    )
  end

  def project do
    [
      app: :nebula_token,
      version: "1.0.1-rc.1",
      elixir: "~> 1.18",
      description:
        "Opaque rotating refresh tokens (RFC 9700 model): rotation, reuse detection, family revocation, sender binding.",
      package: package(),
      docs: docs(),
      deps: deps()
    ]
  end

  def application, do: [extra_applications: [:crypto]]

  defp package do
    [
      # Hex takes a list even for a single grant; one entry means one licence.
      licenses: ["Apache-2.0"],
      maintainers: ["Matteo Teodori"],
      # Explicit rather than relying on Hex's default file set (lib/priv/mix.exs
      # plus a handful of well-known names): an allow-list states exactly what
      # the tarball carries, and LICENSE is not optional. test/ is deliberately
      # absent — conformance is verified from a repository checkout
      # (RELEASING.md).
      files: [
        "lib",
        "mix.exs",
        "README.md",
        "skills/nebula-token-elixir/SKILL.md",
        "CHANGELOG.md",
        "LICENSE"
      ],
      links: %{
        "Website" => "https://nebulatoken.dev",
        "GitHub" => "https://github.com/nebula-token/nebula-token",
        "Specification" =>
          "https://github.com/nebula-token/nebula-token/blob/main/SPECIFICATION.md",
        "Changelog" => "https://github.com/nebula-token/nebula-token/blob/main/CHANGELOG.md",
        "Issues" => "https://github.com/nebula-token/nebula-token/issues"
      }
    ]
  end

  defp docs do
    [
      main: "NebulaToken",
      extras: ["README.md"]
    ]
  end

  defp deps do
    [
      # Test-only: decodes the shared conformance vectors in spec/. The library
      # itself has no runtime dependency beyond :crypto.
      {:jason, "~> 1.4", only: :test}
    ]
  end
end
