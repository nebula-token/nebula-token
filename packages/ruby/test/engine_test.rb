# frozen_string_literal: true

# Language-specific tests: properties that cannot be expressed as portable
# behavior vectors. Every cross-language behavior lives in
# spec/behavior-vectors.json and is exercised by behavior_test.rb.
#
# Run: ruby -Ilib test/engine_test.rb
require 'minitest/autorun'
require 'json'
require 'nebula-token' # the dashed shim; loads lib/nebula_token.rb

class EngineTest < Minitest::Test
  PEPPER = 'pepper-one-0123456789abcdef0123456789ab'
  PEPPER2 = 'pepper-two-0123456789abcdef0123456789ab'
  HASH = ('a' * 64)

  class Clock
    attr_accessor :now

    def initialize(now = 1_700_000_000)
      @now = now
    end

    def to_proc = -> { @now }
  end

  def make_engine(store: nil, clock: nil, **overrides)
    store ||= NebulaToken::MemoryRefreshTokenStore.new
    clock ||= Clock.new
    engine = NebulaToken::Engine.new(
      **{ peppers: { 'k1' => PEPPER }, active_kid: 'k1', store: store, clock: clock.to_proc }
        .merge(overrides)
    )
    [engine, store, clock]
  end

  def selector_of(token) = token.split('.')[2]

  # ── Packaging (Ruby-specific) ───────────────────────────────────────────────

  def test_the_library_loads_without_the_base64_gem
    # `base64` stopped being a default gem in Ruby 3.4. A `require 'base64'`
    # here, undeclared in the gemspec, raises LoadError under Bundler on a
    # current Ruby — the gem would not load at all inside a Rails app.
    refute defined?(::Base64), 'nebula_token must not pull in the base64 gem'
    assert_empty $LOADED_FEATURES.grep(%r{/base64\.rb\z})
  end

  def test_both_require_spellings_load_the_library
    require 'nebula_token' # the underscored file name
    assert defined?(NebulaToken::Engine)
  end

  def test_base64url_round_trip_without_base64
    [1, 2, 3, 16, 31, 32, 33, 64].each do |n|
      bytes = SecureRandom.bytes(n)
      encoded = NebulaToken.b64url_encode(bytes)
      assert_nil encoded[/[+\/=]/], "encoding must be unpadded base64url: #{encoded}"
      assert_equal bytes, NebulaToken.b64url_decode(encoded)
    end
    assert_nil NebulaToken.b64url_decode('A')      # impossible length
    assert_nil NebulaToken.b64url_decode('AA==')   # padding is not in the alphabet
    assert_nil NebulaToken.b64url_decode(nil)
  end

  # ── Parsing on the attacker-reachable path ([N-8]) ──────────────────────────

  def test_a_token_carrying_invalid_utf8_is_malformed_not_an_exception
    engine, = make_engine
    # What Rack hands you from a cookie: bytes tagged UTF-8 that are not UTF-8.
    # String#split raises ArgumentError on these, which would turn one hostile
    # byte into an unauthenticated 500 on the refresh endpoint.
    hostile = "nbl.k1.AAECAwQFBgcICQoLDA0OD\xFF.#{'A' * 43}".dup.force_encoding(Encoding::UTF_8)
    refute_predicate hostile, :valid_encoding?

    assert_equal 'MALFORMED', engine.refresh(hostile).error
    assert_equal 'MALFORMED', engine.revoke_token(hostile).error
    assert_nil NebulaToken.parse_token(hostile)
  end

  def test_refresh_and_revoke_never_raise_on_hostile_strings
    engine, = make_engine
    [nil, 42, '', 'garbage', "\xC3".dup.force_encoding(Encoding::UTF_8),
     'nbl.k1.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'.encode('UTF-16LE')].each do |bad|
      assert_equal 'MALFORMED', engine.refresh(bad).error, bad.inspect[0, 40]
      assert_equal 'MALFORMED', engine.revoke_token(bad).error, bad.inspect[0, 40]
    end
  end

  # ── Constant-time comparison ([N-31]) ───────────────────────────────────────

  def test_constant_time_equal_hex_rejects_anything_that_is_not_64_lowercase_hex
    assert NebulaToken.constant_time_equal_hex(HASH, HASH)
    refute NebulaToken.constant_time_equal_hex(HASH, 'b' * 64)

    # A lenient hex decode stops at the first invalid character and compares
    # decoded prefixes, so every case below would otherwise compare EQUAL.
    refute NebulaToken.constant_time_equal_hex('abc', 'abd'), 'odd-length prefixes'
    refute NebulaToken.constant_time_equal_hex(HASH, "#{HASH}   "), 'space-padded CHAR column'
    refute NebulaToken.constant_time_equal_hex(HASH, "#{HASH}\n"), 'trailing newline'
    refute NebulaToken.constant_time_equal_hex(HASH, "#{HASH}zzzz"), 'junk suffix'
    refute NebulaToken.constant_time_equal_hex(HASH, HASH.upcase), 'case is not folded'
    refute NebulaToken.constant_time_equal_hex(HASH[0, 63], HASH[0, 63]), 'truncated column'
    refute NebulaToken.constant_time_equal_hex('', ''), 'empty is never equal'
  end

  def test_constant_time_equal_hex_never_raises
    [nil, 42, [], {}, '', 'zz', ' ' * 64, HASH.encode('UTF-16LE'),
     "\xFF".dup.force_encoding(Encoding::UTF_8)].each do |hostile|
      refute NebulaToken.constant_time_equal_hex(hostile, HASH), hostile.inspect[0, 30]
      refute NebulaToken.constant_time_equal_hex(HASH, hostile), hostile.inspect[0, 30]
    end
  end

  def test_a_stored_hash_corrupted_after_the_fact_fails_closed
    engine, store, = make_engine
    issued = engine.issue('u1')
    row = store.all.first
    # The same record, but an ETL job upper-cased the column.
    store.insert(NebulaToken::TokenRecord.new(**row.to_h.merge(
      selector: 'x' * 22, verifier_hash: row.verifier_hash.upcase
    )))

    parts = issued.token.split('.')
    result = engine.refresh("nbl.k1.#{'x' * 22}.#{parts[3]}")
    refute_predicate result, :ok?
    assert_equal 'VERIFIER_MISMATCH', result.error
  end

  # ── Status coercion at the store boundary ───────────────────────────────────

  # A row object that is not a TokenRecord and reports its status as the
  # database String — what ActiveRecord, Sequel, pg, Redis and JSON all return.
  RawRow = Struct.new(:selector, :verifier_hash, :kid, :family_id, :generation, :user_id,
                      :device_id_hash, :created_at, :family_expires_at, :idle_expires_at,
                      :status, :rotated_at, :replaced_by_selector, keyword_init: true)

  class StringStatusStore
    include NebulaToken::RefreshTokenStore

    attr_reader :inner
    attr_accessor :status_override

    def initialize
      @inner = NebulaToken::MemoryRefreshTokenStore.new
    end

    def find_by_selector(selector)
      row = @inner.find_by_selector(selector)
      return nil if row.nil?

      RawRow.new(**row.to_h.merge(status: (@status_override || row.status.to_s)))
    end

    def insert(record) = @inner.insert(record)
    def revoke_family(family_id) = @inner.revoke_family(family_id)
    def revoke_user(user_id) = @inner.revoke_user(user_id)
    def revoke_if_active(selector) = @inner.revoke_if_active(selector)

    def mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
      @inner.mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
    end
  end

  def test_a_status_that_is_not_exactly_active_is_never_rotated
    store = StringStatusStore.new
    engine, = make_engine(store: store)
    issued = engine.issue('u1')

    # The String spelling of the status must still rotate: the guard is
    # fail-closed, not blanket denial.
    assert_predicate engine.refresh(issued.token), :ok?

    store.status_override = 'revoked'
    assert_equal 'REVOKED', engine.refresh(issued.token).error
    store.status_override = 'rotated'
    assert_equal 'REUSE_DETECTED', engine.refresh(issued.token).error

    # Anything unrecognised — a column default, a locale-cased value, a typo in
    # a migration — must refuse rather than fall through to rotation.
    ['Active', 'ACTIVE', 'active ', '', 'pending', nil, 7].each do |weird|
      store.status_override = weird
      assert_equal 'REVOKED', engine.refresh(issued.token).error, weird.inspect
    end
  end

  def test_token_record_normalises_the_status_it_is_given
    row = lambda { |status|
      NebulaToken::TokenRecord.new(
        selector: 'A' * 22, verifier_hash: HASH, kid: 'k1', family_id: 'f', generation: 0,
        user_id: 'u1', created_at: 0, family_expires_at: 1, idle_expires_at: 1, status: status
      ).status
    }
    assert_equal :active, row.call('active')
    assert_equal :rotated, row.call(:rotated)
    assert_equal :revoked, row.call('revoked')
    [nil, 'ACTIVE', 'unknown', 0, :pending].each { |weird| assert_equal :revoked, row.call(weird), weird.inspect }
  end

  def test_token_record_coerces_integer_columns
    record = NebulaToken::TokenRecord.new(
      selector: 'A' * 22, verifier_hash: HASH, kid: 'k1', family_id: 'f', generation: '3',
      user_id: 'u1', created_at: '1700000000', family_expires_at: '1700003600',
      idle_expires_at: '1700000600', status: 'active', rotated_at: nil
    )
    assert_equal 3, record.generation
    assert_equal 1_700_000_000, record.created_at
    assert_nil record.rotated_at
  end

  # ── Concurrency ([N-17], [N-34]) ────────────────────────────────────────────

  # A one-shot barrier: every racer parks until `parties` of them have arrived.
  class Barrier
    def initialize(parties)
      @parties = parties
      @arrived = 0
      @released = false
      @mutex = Mutex.new
      @cond = ConditionVariable.new
    end

    def wait
      @mutex.synchronize do
        return if @released

        @arrived += 1
        if @arrived >= @parties
          @released = true
          @cond.broadcast
        else
          @cond.wait(@mutex) until @released
        end
      end
    end
  end

  # Holds every refresh at the moment it has read the record but not yet
  # written: precisely the interleaving the compare-and-set exists for.
  class RacingStore
    include NebulaToken::RefreshTokenStore

    attr_reader :inner

    def initialize(parties)
      @inner = NebulaToken::MemoryRefreshTokenStore.new
      @barrier = Barrier.new(parties)
    end

    def find_by_selector(selector)
      row = @inner.find_by_selector(selector)
      @barrier.wait
      row
    end

    def insert(record) = @inner.insert(record)
    def revoke_if_active(selector) = @inner.revoke_if_active(selector)
    def revoke_family(family_id) = @inner.revoke_family(family_id)
    def revoke_user(user_id) = @inner.revoke_user(user_id)

    def mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
      @inner.mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
    end
  end

  def test_concurrent_refreshes_of_one_token_leave_exactly_one_active_record
    racers = 8
    store = RacingStore.new(racers)
    engine, = make_engine(store: store)
    token = engine.issue('u1').token

    threads = Array.new(racers) { Thread.new { engine.refresh(token) } }
    threads.each { |t| assert t.join(20), 'a concurrent refresh deadlocked' }
    results = threads.map(&:value)

    winners = results.select(&:ok?)
    losers = results.reject(&:ok?)
    assert_equal 1, winners.length, 'exactly one refresh may win the compare-and-set'
    assert_equal [], losers.map(&:error).uniq - ['CONFLICT'], 'every loser must report CONFLICT'
    assert_equal racers - 1, losers.length

    rows = store.inner.all
    assert_equal 1, rows.count(&:active?), 'the family must not fork into two live lineages'
    assert_equal 1, rows.count(&:rotated?)
    # [N-35]: a CONFLICT revokes nothing beyond the successor the engine itself
    # inserted, so the winner's token still works.
    assert_predicate engine.refresh(winners.first.token), :ok?
  end

  # The same race, against a store that reports the affected-row count instead
  # of a boolean — which is what `docs/STORE.md` §4 tells an adapter to derive
  # its answer from, naming `cmd_tuples` on a `PG::Result` by hand. Ruby's only
  # falsy values are `nil` and `false`, so a lost compare-and-set returning `0`
  # reads as applied unless the engine normalises it ([N-17], [N-18]).
  class CountingCasStore < RacingStore
    def mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
      super ? 1 : 0
    end

    def revoke_if_active(selector)
      super ? 1 : 0
    end
  end

  def test_a_store_reporting_affected_row_counts_cannot_fork_a_family
    racers = 8
    store = CountingCasStore.new(racers)
    engine, = make_engine(store: store)
    token = engine.issue('u1').token

    threads = Array.new(racers) { Thread.new { engine.refresh(token) } }
    threads.each { |t| assert t.join(20), 'a concurrent refresh deadlocked' }
    results = threads.map(&:value)

    assert_equal 1, results.count(&:ok?),
                 '0 is truthy in Ruby: a lost compare-and-set must not read as applied'
    assert_equal [], results.reject(&:ok?).map(&:error).uniq - ['CONFLICT']

    rows = store.inner.all
    assert_equal 1, rows.count(&:active?), 'the family must not fork into two live lineages'
    assert_equal 1, rows.count(&:rotated?)
  end

  def test_cas_applied_accepts_a_count_and_fails_closed_on_anything_else
    assert NebulaToken.cas_applied?(true)
    assert NebulaToken.cas_applied?(1)
    assert NebulaToken.cas_applied?(2)

    refute NebulaToken.cas_applied?(false)
    refute NebulaToken.cas_applied?(0)
    refute NebulaToken.cas_applied?(nil)
    # Out of contract: a spurious CONFLICT revokes nothing and is retryable
    # ([N-35]); a spurious success forks a family and cannot be undone.
    refute NebulaToken.cas_applied?('1')
    refute NebulaToken.cas_applied?(Object.new)
  end

  # ── Store failures fail closed ([N-20]) ─────────────────────────────────────

  class StoreDown < StandardError; end

  class ExplodingStore
    include NebulaToken::RefreshTokenStore

    def initialize(fail_on)
      @inner = NebulaToken::MemoryRefreshTokenStore.new
      @fail_on = fail_on
    end

    def find_by_selector(selector)
      guard(:find_by_selector) { @inner.find_by_selector(selector) }
    end

    def insert(record)
      guard(:insert) { @inner.insert(record) }
    end

    def mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
      guard(:mark_rotated) { @inner.mark_rotated(selector, from_status, rotated_at, replaced_by_selector) }
    end

    def revoke_if_active(selector)
      guard(:revoke_if_active) { @inner.revoke_if_active(selector) }
    end

    def revoke_family(family_id)
      guard(:revoke_family) { @inner.revoke_family(family_id) }
    end

    def revoke_user(user_id)
      guard(:revoke_user) { @inner.revoke_user(user_id) }
    end

    private

    def guard(method)
      raise StoreDown, 'database is on fire' if method == @fail_on

      yield
    end
  end

  def test_a_failing_insert_never_hands_back_a_token_for_state_that_was_not_written
    engine, = make_engine(store: ExplodingStore.new(:insert))
    assert_raises(StoreDown) { engine.issue('u1') }
  end

  def test_a_failing_revoke_family_is_not_reported_as_a_successful_revocation
    store = ExplodingStore.new(:revoke_family)
    engine, = make_engine(store: store)
    issued = engine.issue('u1')
    assert_predicate engine.refresh(issued.token), :ok?

    # The replay must attempt a family revocation; the exception propagates
    # rather than being swallowed into a confident REUSE_DETECTED ([N-20]).
    assert_raises(StoreDown) { engine.refresh(issued.token) }
    assert_raises(StoreDown) { engine.revoke_token(issued.token) }
  end

  def test_a_failing_lookup_propagates_instead_of_becoming_not_found
    engine, = make_engine(store: ExplodingStore.new(:find_by_selector))
    token = 'nbl.k1.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
    assert_raises(StoreDown) { engine.refresh(token) }
  end

  # ── Configuration (§5, [N-23], [N-24]) ──────────────────────────────────────

  def test_constructor_validation
    store = NebulaToken::MemoryRefreshTokenStore.new
    bad = lambda { |**cfg|
      assert_raises(NebulaToken::ConfigError) do
        NebulaToken::Engine.new(**{ peppers: { 'k1' => PEPPER }, active_kid: 'k1', store: store }.merge(cfg))
      end
    }

    bad.call(peppers: { 'k1' => 'short' })
    bad.call(active_kid: 'nope')
    bad.call(peppers: { 'k.1' => PEPPER }, active_kid: 'k.1')   # '.' is not in the kid alphabet
    bad.call(peppers: { 'k 1' => PEPPER }, active_kid: 'k 1')
    bad.call(peppers: { '' => PEPPER }, active_kid: '')
    bad.call(peppers: { 'k' * 65 => PEPPER }, active_kid: 'k' * 65)
    bad.call(peppers: {})
    bad.call(peppers: { 'k1' => nil })
    bad.call(absolute_ttl_seconds: 0)
    bad.call(idle_ttl_seconds: -5)
    bad.call(reuse_grace_seconds: -1)
    # [N-11] a pepper whose BYTES are not valid UTF-8 is not a usable HMAC key,
    # whatever the String's encoding tag says. Well over the byte floor, so
    # only the encoding rule can reject it.
    bad.call(peppers: { 'k1' => ("\xED\xA0\x80".b + PEPPER.b).force_encoding('UTF-8') })
    bad.call(peppers: { 'k1' => ("\xED\xA0\x80".b + PEPPER.b) })
    bad.call(absolute_ttl_seconds: 1.5)

    # ConfigError is an ArgumentError, so existing rescue clauses keep working.
    assert_operator NebulaToken::ConfigError, :<, ArgumentError
  end

  def test_a_kid_of_exactly_max_kid_length_is_accepted
    store = NebulaToken::MemoryRefreshTokenStore.new
    kid = 'k' * NebulaToken::MAX_KID_LENGTH
    engine = NebulaToken::Engine.new(peppers: { kid => PEPPER }, active_kid: kid, store: store)
    assert_equal kid, engine.issue('u1').token.split('.')[1]
  end

  def test_min_pepper_length_counts_bytes_not_characters
    store = NebulaToken::MemoryRefreshTokenStore.new
    wide = '日' * 16 # 16 characters, 48 UTF-8 bytes
    assert_equal 16, wide.length
    assert_equal 48, wide.bytesize
    NebulaToken::Engine.new(peppers: { 'k1' => wide }, active_kid: 'k1', store: store)

    narrow = '日' * 10 # 10 characters, 30 bytes — under the floor
    assert_raises(NebulaToken::ConfigError) do
      NebulaToken::Engine.new(peppers: { 'k1' => narrow }, active_kid: 'k1', store: store)
    end
    assert_raises(NebulaToken::ConfigError) do
      NebulaToken::Engine.new(peppers: { 'k1' => 'a' * 31 }, active_kid: 'k1', store: store)
    end
  end

  def test_the_pepper_map_is_copied_so_the_caller_cannot_weaken_the_engine
    store = NebulaToken::MemoryRefreshTokenStore.new
    secret = +PEPPER
    peppers = { 'k1' => secret }
    engine = NebulaToken::Engine.new(peppers: peppers, active_kid: 'k1', store: store)

    secret << 'tampered'  # Ruby Strings are mutable: a copy of the Hash is not enough
    peppers['k1'] = 'x'   # would otherwise key the HMAC with a one-byte secret
    peppers.delete('k1')

    issued = engine.issue('u1')
    parsed = NebulaToken.parse_token(issued.token)
    record = store.find_by_selector(parsed.selector)
    assert_equal NebulaToken.hash_verifier(PEPPER, parsed.verifier), record.verifier_hash
    assert_predicate engine.refresh(issued.token), :ok?
  end

  def test_the_engine_never_prints_a_pepper_in_a_debug_representation
    engine, = make_engine(peppers: { 'k1' => PEPPER, 'k2' => PEPPER2 })
    # [N-46]: Object#inspect prints every instance variable, and @peppers holds
    # the HMAC keys — `p engine` in a console or an error page that dumps ivars
    # would put the whole key set in a log.
    [engine.inspect, engine.to_s, "#{engine}"].each do |text|
      refute_includes text, PEPPER, 'a pepper reached a debug representation ([N-46])'
      refute_includes text, PEPPER2, 'a pepper reached a debug representation ([N-46])'
    end
    assert_includes engine.inspect, 'k1', 'the kid is not a secret and stays useful for debugging'
  end

  def test_the_error_message_never_contains_the_pepper
    store = NebulaToken::MemoryRefreshTokenStore.new
    error = assert_raises(NebulaToken::ConfigError) do
      NebulaToken::Engine.new(peppers: { 'k1' => 'too-short' }, active_kid: 'k1', store: store)
    end
    refute_includes error.message, 'too-short', 'a pepper must never appear in an error ([N-46])'
  end

  # ── Device identifiers ([N-11], [N-12], [N-14]) ─────────────────────────────

  def test_issue_rejects_a_device_id_that_is_not_valid_unicode
    engine, = make_engine
    lone_surrogate = "\xED\xA0\x80".dup.force_encoding(Encoding::UTF_8)
    refute_predicate lone_surrogate, :valid_encoding?
    # [N-12]: at issue the value comes from the application, so it surfaces at
    # the call site instead of minting a binding nothing can satisfy.
    assert_raises(NebulaToken::ConfigError) { engine.issue('u1', lone_surrogate) }
    assert_raises(NebulaToken::ConfigError) { engine.issue('u1', "\xFF".dup.force_encoding('UTF-8')) }
  end

  def test_a_binary_tagged_device_id_hashes_as_its_bytes_like_the_other_nine_ports
    utf8 = 'dispositivo-cafè-日本語'
    binary = utf8.b
    assert_equal Encoding::BINARY, binary.encoding
    assert_equal utf8.bytes, binary.bytes, 'the two differ only by their encoding tag'

    # [N-11] keys the HMAC on the UTF-8 encoding of the identifier, and these
    # are the same bytes. Deciding on the tag instead would refuse the binary
    # one — and in refresh that is a sender-binding failure, so Ruby would
    # revoke the family where the other nine rotate.
    assert_equal NebulaToken.hash_device_id(PEPPER, utf8),
                 NebulaToken.hash_device_id(PEPPER, binary)

    engine, = make_engine
    issued = engine.issue('u1', utf8)
    assert_predicate engine.refresh(issued.token, binary), :ok?
  end

  def test_hash_device_id_applies_no_normalisation_trimming_or_case_folding
    nfc = "Café"  # e-acute as one code point
    nfd = "Café" # e + combining acute: the same text, different bytes
    refute_equal NebulaToken.hash_device_id(PEPPER, nfc), NebulaToken.hash_device_id(PEPPER, nfd),
                 'NFC and NFD must not be conflated'
    refute_equal NebulaToken.hash_device_id(PEPPER, 'x'), NebulaToken.hash_device_id(PEPPER, ' x')
    refute_equal NebulaToken.hash_device_id(PEPPER, 'x'), NebulaToken.hash_device_id(PEPPER, 'X')
  end

  def test_an_absent_device_id_is_distinguishable_from_an_empty_one
    engine, store, = make_engine
    unbound = engine.issue('u1')
    bound = engine.issue('u2', '')

    assert_nil store.find_by_selector(selector_of(unbound.token)).device_id_hash
    refute_nil store.find_by_selector(selector_of(bound.token)).device_id_hash
    assert_equal 'DEVICE_MISMATCH', engine.refresh(bound.token).error
  end

  def test_no_raw_secret_appears_in_anything_the_engine_stores
    engine, store, = make_engine
    issued = engine.issue('u1', 'devA')
    dump = JSON.generate(store.all.map(&:to_h))

    refute_includes dump, issued.token.split('.')[3], 'raw verifier'
    refute_includes dump, 'devA', 'raw device identifier'
    refute_includes dump, PEPPER, 'pepper'
  end

  def test_debug_representations_redact_the_credential
    engine, store, = make_engine
    issued = engine.issue('u1', 'devA')
    parsed = NebulaToken.parse_token(issued.token)
    record = store.all.first

    [issued.inspect, issued.to_s, "#{issued}", parsed.inspect, record.inspect].each do |text|
      refute_includes text, issued.token.split('.')[3], "[N-14] leak: #{text[0, 60]}"
    end
    refute_includes record.inspect, record.verifier_hash
    refute_includes engine.refresh(issued.token, 'devA').inspect, 'nbl.'
  end

  # ── Result shape ([N-2], [N-39]) ────────────────────────────────────────────

  def test_timestamps_are_integer_unix_seconds
    engine, = make_engine
    issued = engine.issue('u1')
    assert_kind_of Integer, issued.expires_at
    assert_kind_of Integer, issued.idle_expires_at
    assert_equal 'u1', issued.user_id
    assert_equal 0, issued.generation

    refreshed = engine.refresh(issued.token)
    assert_kind_of Integer, refreshed.expires_at
    assert_kind_of Integer, refreshed.idle_expires_at
    assert_equal issued.expires_at, refreshed.expires_at
  end

  def test_failures_carry_user_id_and_family_id_once_a_record_is_resolved
    engine, = make_engine
    issued = engine.issue('u1')
    engine.refresh(issued.token)

    replay = engine.refresh(issued.token)
    assert_equal 'u1', replay.user_id
    assert_equal issued.family_id, replay.family_id

    # Before a record is resolved there is nothing to attribute ([N-39]).
    unresolved = engine.refresh('garbage')
    assert_nil unresolved.user_id
    assert_nil unresolved.family_id
  end

  def test_error_codes_are_the_ten_published_names
    assert_equal 10, NebulaToken::ErrorCode::ALL.length
    assert_includes NebulaToken::ErrorCode::ALL, 'CONFLICT'
    assert_equal NebulaToken::ErrorCode::ALL, NebulaToken::ErrorCode::ALL.uniq
  end

  # ── Store hygiene ([N-15], [N-19], [N-21]) ──────────────────────────────────

  def test_the_memory_store_refuses_a_duplicate_selector
    store = NebulaToken::MemoryRefreshTokenStore.new
    record = NebulaToken::TokenRecord.new(
      selector: 'A' * 22, verifier_hash: HASH, kid: 'k1', family_id: 'f', generation: 0,
      user_id: 'u1', created_at: 0, family_expires_at: 1, idle_expires_at: 1
    )
    store.insert(record)
    error = assert_raises(RuntimeError) { store.insert(record) }
    assert_match(/duplicate selector/, error.message)
  end

  def test_revocation_counts_are_the_number_of_records_changed_and_idempotent
    engine, store, = make_engine
    a = engine.issue('u1')
    engine.refresh(a.token)
    engine.issue('u2')

    assert_equal 2, engine.revoke_family(a.family_id)
    assert_equal 0, engine.revoke_family(a.family_id)
    assert_equal 0, engine.revoke_all_for_user('u1')
    assert_equal 1, engine.revoke_all_for_user('u2')
    assert_equal 3, store.all.count(&:revoked?)
  end

  def test_delete_expired_only_removes_records_past_the_family_deadline
    engine, store, clock = make_engine(absolute_ttl_seconds: 100, idle_ttl_seconds: 100)
    issued = engine.issue('u1')
    engine.refresh(issued.token)

    # [N-15]: rotated rows ARE the reuse detector; dropping them early turns
    # every replay into NOT_FOUND.
    assert_equal 0, store.delete_expired(clock.now + 99)
    assert_equal 2, store.all.length
    assert_equal 2, store.delete_expired(clock.now + 100)
  end

  def test_the_memory_store_is_usable_from_several_threads
    engine, store, = make_engine
    threads = Array.new(8) { |i| Thread.new { 25.times { engine.issue("u#{i}") } } }
    threads.each { |t| assert t.join(20), 'the in-memory store deadlocked' }
    assert_equal 200, store.all.length
  end
end
