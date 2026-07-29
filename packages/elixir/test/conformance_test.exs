defmodule NebulaToken.ConformanceTest do
  @moduledoc """
  Runner for the shared conformance vectors, `spec/test-vectors.json`
  ([N-47] §9.1).

  Every section asserts that the number of cases it executed equals the number
  published in the file's `counts` block, and that no section is absent or
  empty: silently iterating zero cases is a conformance failure, not a pass
  ([N-48]).
  """
  use ExUnit.Case, async: true

  @vectors NebulaToken.SpecVectors.load("test-vectors.json")

  test "spec version matches the published vectors" do
    assert NebulaToken.spec_version() == @vectors["spec_version"]
  end

  test "every published constant is compared ([N-4], [N-48])" do
    published = @vectors["constants"]

    compared = %{
      "prefix" => NebulaToken.prefix(),
      "selector_bytes" => NebulaToken.selector_bytes(),
      "verifier_bytes" => NebulaToken.verifier_bytes(),
      "selector_chars" => NebulaToken.selector_chars(),
      "verifier_chars" => NebulaToken.verifier_chars(),
      "max_kid_length" => NebulaToken.max_kid_length(),
      "max_token_length" => NebulaToken.max_token_length(),
      "min_pepper_length" => NebulaToken.min_pepper_length(),
      "default_absolute_ttl_seconds" => NebulaToken.default_absolute_ttl(),
      "default_idle_ttl_seconds" => NebulaToken.default_idle_ttl(),
      "default_reuse_grace_seconds" => NebulaToken.default_reuse_grace()
    }

    # Comparing whole maps — not field by field — is what makes a constant that
    # was published but never asserted a failure rather than a silent hole.
    assert compared == published
    assert map_size(published) == 11
  end

  test "verifier hashing vectors ([N-11], [N-13])" do
    executed =
      Enum.reduce(section!("verifier_hashing"), 0, fn v, n ->
        {:ok, verifier} = Base.url_decode64(v["verifier_b64url"], padding: false)

        assert NebulaToken.hash_verifier(v["pepper"], verifier) ==
                 v["expected_hmac_sha256_hex"],
               "#{v["id"]}: #{v["note"]}"

        n + 1
      end)

    assert executed == @vectors["counts"]["verifier_hashing"],
           "executed count must equal the published count ([N-48])"
  end

  test "device hashing vectors ([N-11], [N-13])" do
    executed =
      Enum.reduce(section!("device_hashing"), 0, fn v, n ->
        assert NebulaToken.hash_device_id(v["pepper"], v["device_id"]) ==
                 v["expected_hmac_sha256_hex"],
               "#{v["id"]}: #{v["note"]}"

        n + 1
      end)

    assert executed == @vectors["counts"]["device_hashing"],
           "executed count must equal the published count ([N-48])"
  end

  test "parsing vectors ([N-5]..[N-9])" do
    executed =
      Enum.reduce(section!("parsing"), 0, fn v, n ->
        case NebulaToken.parse_token(v["token"]) do
          {:ok, parsed} ->
            assert v["valid"], "#{v["id"]} must be MALFORMED: #{v["note"]}"
            assert parsed.kid == v["kid"], v["id"]
            assert parsed.selector == v["selector"], v["id"]
            assert byte_size(parsed.verifier) == NebulaToken.verifier_bytes(), v["id"]

          :error ->
            refute v["valid"], "#{v["id"]} must parse: #{v["note"]}"
        end

        n + 1
      end)

    assert executed == @vectors["counts"]["parsing"],
           "executed count must equal the published count ([N-48])"
  end

  test "parsing is total: nothing raises, on any input ([N-8])" do
    hostile = [
      nil,
      42,
      :not_a_string,
      [],
      {},
      %{},
      ~c"nbl.k1.charlist",
      "",
      " ",
      ".",
      String.duplicate(".", 1_000),
      "nbl." <> String.duplicate("k", 10_000),
      "nbl.k1." <> String.duplicate(" ", 22) <> "." <> String.duplicate("A", 43),
      # Invalid UTF-8: a bare continuation byte, and the WTF-8 spelling of an
      # unpaired surrogate. Neither has a String representation, and neither may
      # perturb the parser.
      <<0xFF, 0xFE>>,
      <<0xED, 0xA0, 0x80>>,
      "nbl.k1.AAECAwQFBgcICQoLDA0ODw." <> :binary.copy(<<0xFF>>, 43)
    ]

    for input <- hostile do
      assert NebulaToken.parse_token(input) == :error, "parse_token(#{inspect(input)})"
    end
  end

  defp section!(name) do
    section = @vectors[name]

    # [N-48]: a missing or empty section must fail loudly, not iterate zero
    # times and report success.
    assert is_list(section) and section != [], "vector section #{name} is absent or empty"
    section
  end
end
