# frozen_string_literal: true

# Shared conformance vectors — spec/test-vectors.json (SPECIFICATION.md [N-47]).
#
# Run: ruby -Ilib test/conformance_test.rb
require 'minitest/autorun'
require 'json'
require 'nebula_token'

class ConformanceTest < Minitest::Test
  # The vectors live at <repo root>/spec. Found by walking up from this file, so
  # the package neither hardcodes an absolute path nor vendors a stale copy.
  def self.spec_dir
    dir = File.expand_path(__dir__)
    loop do
      candidate = File.join(dir, 'spec')
      return candidate if File.file?(File.join(candidate, 'test-vectors.json'))

      parent = File.dirname(dir)
      raise "spec/test-vectors.json not found in any parent of #{__dir__}" if parent == dir

      dir = parent
    end
  end

  VECTORS = JSON.parse(File.read(File.join(spec_dir, 'test-vectors.json'), encoding: 'UTF-8')).freeze

  # Every constant published in the vectors, mapped to the value this package
  # exposes ([N-4]). The key sets are compared below, so a constant added to the
  # vectors cannot slip through unasserted ([N-48]).
  CONSTANTS = {
    'prefix' => NebulaToken::PREFIX,
    'selector_bytes' => NebulaToken::SELECTOR_BYTES,
    'verifier_bytes' => NebulaToken::VERIFIER_BYTES,
    'selector_chars' => NebulaToken::SELECTOR_CHARS,
    'verifier_chars' => NebulaToken::VERIFIER_CHARS,
    'max_kid_length' => NebulaToken::MAX_KID_LENGTH,
    'max_token_length' => NebulaToken::MAX_TOKEN_LENGTH,
    'min_pepper_length' => NebulaToken::MIN_PEPPER_LENGTH,
    'default_absolute_ttl_seconds' => NebulaToken::DEFAULT_ABSOLUTE_TTL,
    'default_idle_ttl_seconds' => NebulaToken::DEFAULT_IDLE_TTL,
    'default_reuse_grace_seconds' => NebulaToken::DEFAULT_REUSE_GRACE
  }.freeze

  def test_spec_version_matches_the_published_vectors
    assert_equal VECTORS['spec_version'], NebulaToken::SPEC_VERSION
  end

  def test_every_published_section_is_present_and_non_empty
    # [N-48]: silently iterating zero cases is a conformance failure, not a pass.
    refute_empty VECTORS['constants'], 'constants section is absent or empty'
    %w[verifier_hashing device_hashing parsing].each do |section|
      refute_empty VECTORS[section].to_a, "#{section} section is absent or empty"
      assert_equal VECTORS['counts'][section], VECTORS[section].length,
                   "#{section}: published count disagrees with the published cases"
    end
  end

  def test_constants_match_the_specification
    published = VECTORS['constants']
    assert_equal published.keys.sort, CONSTANTS.keys.sort,
                 'a constant was published but never asserted ([N-48])'
    CONSTANTS.each { |name, value| assert_equal published[name], value, name }
  end

  def test_verifier_hashing_vectors
    executed = 0
    VECTORS['verifier_hashing'].each do |v|
      verifier = NebulaToken.b64url_decode(v['verifier_b64url'])
      refute_nil verifier, v['id']
      assert_equal v['expected_hmac_sha256_hex'],
                   NebulaToken.hash_verifier(v['pepper'], verifier), "#{v['id']}: #{v['note']}"
      executed += 1
    end
    assert_equal VECTORS['counts']['verifier_hashing'], executed,
                 'executed count must equal the published count ([N-48])'
  end

  def test_device_hashing_vectors
    executed = 0
    VECTORS['device_hashing'].each do |v|
      assert_equal v['expected_hmac_sha256_hex'],
                   NebulaToken.hash_device_id(v['pepper'], v['device_id']), "#{v['id']}: #{v['note']}"
      executed += 1
    end
    assert_equal VECTORS['counts']['device_hashing'], executed,
                 'executed count must equal the published count ([N-48])'
  end

  def test_parsing_vectors
    executed = 0
    VECTORS['parsing'].each do |v|
      parsed = NebulaToken.parse_token(v['token'])
      if v['valid']
        refute_nil parsed, "#{v['id']} should parse: #{v['note']}"
        assert_equal v['kid'], parsed.kid, v['id']
        assert_equal v['selector'], parsed.selector, v['id']
        assert_equal NebulaToken::VERIFIER_BYTES, parsed.verifier.bytesize, v['id']
      else
        assert_nil parsed, "#{v['id']} should be MALFORMED (#{v['rule']}): #{v['note']}"
      end
      executed += 1
    end
    assert_equal VECTORS['counts']['parsing'], executed,
                 'executed count must equal the published count ([N-48])'
  end

  VALID_TOKEN = 'nbl.k1.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'

  # [N-8]: parsing is total. A Ruby String is bytes plus an encoding tag, so the
  # hostile inputs below include values on which String#split and Regexp#match?
  # raise ArgumentError — exactly what a cookie carrying one stray byte produces.
  def test_parsing_never_raises_and_rejects_hostile_input
    hostile = [
      nil, 42, :symbol, [], {}, Object.new,
      '', ' ', '.' * 1000, "nbl.#{'k' * 10_000}",
      "nbl.k1.#{' ' * 22}.#{'A' * 43}",
      "\xFF\xFE".dup.force_encoding(Encoding::UTF_8),                      # invalid UTF-8
      "#{VALID_TOKEN}\xC3".dup.force_encoding(Encoding::UTF_8),            # truncated multi-byte tail
      VALID_TOKEN.encode(Encoding::UTF_16LE),                              # not ASCII-compatible
      "nbl.k1.AAECAwQFBgcICQoLDA0OD\xFF.#{'A' * 43}".dup.force_encoding(Encoding::UTF_8)
    ]

    hostile.each do |input|
      assert_nil NebulaToken.parse_token(input), "parse_token(#{input.inspect[0, 48]}) should be nil"
    rescue StandardError => e
      flunk "parse_token(#{input.inspect[0, 48]}) raised #{e.class}: #{e.message}"
    end
  end

  def test_a_binary_encoded_token_parses_to_the_same_value
    # Rack hands out ASCII-8BIT strings; the bytes are what matters, not the tag.
    binary = NebulaToken.parse_token(VALID_TOKEN.dup.force_encoding(Encoding::ASCII_8BIT))
    refute_nil binary
    assert_equal 'k1', binary.kid
    assert_equal 'AAECAwQFBgcICQoLDA0ODw', binary.selector
  end
end
