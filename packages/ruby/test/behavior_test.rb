# frozen_string_literal: true

# Normative behavioral suite — spec/behavior-vectors.json (SPECIFICATION.md
# [N-47], [N-49]).
#
# The scenarios are data. The runner below is the only language-specific part,
# which is what stops the ten ports from drifting apart the way ten hand-written
# suites did. Nothing here re-derives a case: if a behavior is not in the vector
# file, it belongs in engine_test.rb instead.
#
# Run: ruby -Ilib test/behavior_test.rb
require 'minitest/autorun'
require 'json'
require 'nebula_token'

# Executes the published scenarios against an injected clock and a store that
# can be told to lose one compare-and-set.
class BehaviorRunner
  # The vectors live at <repo root>/spec. Found by walking up from this file, so
  # the package neither hardcodes an absolute path nor vendors a stale copy.
  def self.spec_dir
    dir = File.expand_path(__dir__)
    loop do
      candidate = File.join(dir, 'spec')
      return candidate if File.file?(File.join(candidate, 'behavior-vectors.json'))

      parent = File.dirname(dir)
      raise "spec/behavior-vectors.json not found in any parent of #{__dir__}" if parent == dir

      dir = parent
    end
  end

  def self.load_vectors
    JSON.parse(File.read(File.join(spec_dir, 'behavior-vectors.json'), encoding: 'UTF-8')).freeze
  end

  # Conditions this runtime satisfies. A Ruby String is bytes plus an encoding
  # tag, so it can hold the UTF-8 spelling of an unpaired surrogate (invalid
  # Unicode) just as a JavaScript or Java string can — the scenario applies.
  SATISFIED_CONDITIONS = ['runtime-admits-invalid-unicode-strings'].freeze

  # 32 zero bytes, canonically encoded: well formed, and never the real secret.
  FORGED_VERIFIER = ('A' * NebulaToken::VERIFIER_CHARS).freeze
  FORGED_SELECTOR = ('A' * NebulaToken::SELECTOR_CHARS).freeze
  # U+D800 has no legal UTF-8 encoding; these are its CESU-8 bytes, tagged UTF-8.
  LONE_SURROGATE = "\xED\xA0\x80".dup.force_encoding(Encoding::UTF_8).freeze

  # A divergence from a published scenario is raised as Minitest::Assertion
  # ITSELF, never as a subclass of it. Minitest's StatisticsReporter buckets
  # results with `results.group_by { |r| r.failure.class }` and then counts
  # `aggregate[Assertion].size` — an exact class match. A subclass therefore
  # lands in a bucket that is counted as neither a failure nor an error, and the
  # summary line reads "0 failures, 0 errors" for a run that diverged from the
  # normative vectors. See the regression guard in BehaviorTest.
  SCENARIO_FAILURE = Minitest::Assertion

  TokenBinding = Struct.new(:token, :family_id, :expires_at)
  RunOutcome = Struct.new(:executed, :skipped)
  Skipped = Struct.new(:id, :condition)

  # Wraps the reference store so a scenario can force one compare-and-set to lose.
  class ControllableStore
    include NebulaToken::RefreshTokenStore

    attr_reader :inner

    def initialize
      @inner = NebulaToken::MemoryRefreshTokenStore.new
      @fail_next = {}
    end

    def fail_next_cas(method)
      @fail_next[method] = true
    end

    def find_by_selector(selector) = @inner.find_by_selector(selector)
    def insert(record) = @inner.insert(record)
    def revoke_family(family_id) = @inner.revoke_family(family_id)
    def revoke_user(user_id) = @inner.revoke_user(user_id)

    def mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
      return false if consume('markRotated')

      @inner.mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
    end

    def revoke_if_active(selector)
      return false if consume('revokeIfActive')

      @inner.revoke_if_active(selector)
    end

    private

    def consume(method)
      @fail_next.delete(method) ? true : false
    end
  end

  def initialize(vectors)
    @vectors = vectors
  end

  def self.applicable?(scenario)
    scenario['condition'].nil? || SATISFIED_CONDITIONS.include?(scenario['condition'])
  end

  # Execute every applicable scenario. Raises on the first divergence.
  def run_all
    outcome = RunOutcome.new([], [])
    @vectors['scenarios'].each do |scenario|
      unless self.class.applicable?(scenario)
        outcome.skipped << Skipped.new(scenario['id'], scenario['condition'])
        next
      end
      run_scenario(scenario)
      outcome.executed << scenario['id']
    end
    outcome
  end

  def run_scenario(scenario)
    @scenario = scenario
    cfg = @vectors['defaults'].merge(scenario['config'] || {})
    @store = ControllableStore.new
    @bindings = {}
    @issued_secrets = []
    @device_ids = []
    @now = cfg['now']
    @cfg = cfg
    @engine = build_engine(cfg['peppers'], cfg['activeKid'])

    scenario['steps'].each_with_index { |step, index| run_step(step, index) }
  end

  private

  def build_engine(kids, active_kid)
    NebulaToken::Engine.new(
      peppers: kids.to_h { |kid| [kid, @vectors['peppers'].fetch(kid)] },
      active_kid: active_kid,
      store: @store,
      absolute_ttl_seconds: @cfg['absoluteTtlSeconds'],
      idle_ttl_seconds: @cfg['idleTtlSeconds'],
      reuse_grace_seconds: @cfg['reuseGraceSeconds'],
      clock: -> { @now }
    )
  end

  # rubocop:disable Metrics/CyclomaticComplexity
  def run_step(step, index)
    case step['op']
    when 'issue' then op_issue(step, index)
    when 'refresh' then op_refresh(step, index)
    when 'revokeToken' then op_revoke_token(step, index)
    when 'revokeFamilyOf' then op_revoke_family_of(step, index)
    when 'revokeUser' then op_revoke_user(step, index)
    when 'advance' then @now += step['seconds']
    when 'reconfigure' then @engine = build_engine(step['peppers'], step['activeKid'])
    when 'failNextCas' then @store.fail_next_cas(step['method'])
    when 'expectStatusCounts' then op_expect_status_counts(step, index)
    when 'expectNoRawSecrets' then op_expect_no_raw_secrets(index)
    else fail_step(index, "unknown op #{step['op'].inspect}")
    end
  end
  # rubocop:enable Metrics/CyclomaticComplexity

  def op_issue(step, index)
    device_id = device_of(step)
    result = @engine.issue(step['userId'], device_id)
    expect = step['expect']
    fail_step(index, 'expected issue to fail') if expect && expect['ok'] == false
    check_success(result, expect, index)
    bind(step, result)
    @device_ids << device_id unless device_id.nil? || device_id.empty?
  end

  def op_refresh(step, index)
    expect = step['expect']
    result = @engine.refresh(resolve_token(step, index), device_of(step))
    wants_success = expect.nil? || expect['ok'] == true ||
                    (!expect.key?('ok') && !expect.key?('error'))

    if wants_success
      fail_step(index, "expected success, got #{result.error}") unless result.ok?
      check_success(result, expect, index)
      bind(step, result)
    else
      fail_step(index, "expected #{expect['error']}, got success") if result.ok?
      unless result.error == expect['error']
        fail_step(index, "expected #{expect['error']}, got #{result.error}")
      end
      check_attribution(result, expect, index)
    end
  end

  # [N-39] attribution, tri-state. `true` demands the field, `false` demands its
  # ABSENCE — the exclusion list (MALFORMED, UNKNOWN_KID, NOT_FOUND) is a
  # requirement too, and a truthy-only check could never observe it. A key that
  # is absent asserts nothing. In Ruby a result that resolved no record signals
  # it with nil, so nil is the absence this reads.
  def check_attribution(result, expect, index)
    return if expect.nil?

    if expect.key?('hasUserId') && !result.user_id.nil? != expect['hasUserId']
      fail_step(index, "expected user_id #{expect['hasUserId'] ? 'present' : 'absent'} ([N-39])")
    end
    return unless expect.key?('hasFamilyId') && !result.family_id.nil? != expect['hasFamilyId']

    fail_step(index, "expected family_id #{expect['hasFamilyId'] ? 'present' : 'absent'} ([N-39])")
  end

  def op_revoke_token(step, index)
    expect = step['expect']
    result = @engine.revoke_token(resolve_token(step, index))

    if expect && expect['ok'] == false
      fail_step(index, "expected #{expect['error']}, got success") if result.ok?
      unless result.error == expect['error']
        fail_step(index, "expected #{expect['error']}, got #{result.error}")
      end
      # [N-39] governs every failure result, revoke_token's included.
      check_attribution(result, expect, index)
    else
      fail_step(index, "expected success, got #{result.error}") unless result.ok?
      expect_revoked(expect, result.revoked, index)
    end
  end

  def op_revoke_family_of(step, index)
    bound = @bindings.fetch(step['of']) { fail_step(index, "unknown binding #{step['of'].inspect}") }
    expect_revoked(step['expect'], @engine.revoke_family(bound.family_id), index)
  end

  def op_revoke_user(step, index)
    expect_revoked(step['expect'], @engine.revoke_all_for_user(step['userId']), index)
  end

  def op_expect_status_counts(step, index)
    actual = { 'active' => 0, 'rotated' => 0, 'revoked' => 0 }
    @store.inner.all.each { |row| actual[row.status.to_s] += 1 }
    step['counts'].each do |status, want|
      next if actual[status] == want

      fail_step(index, "expected #{want} #{status}, got #{actual[status]} (#{actual})")
    end
  end

  def op_expect_no_raw_secrets(index)
    # to_h, not inspect: TokenRecord#inspect redacts the hashes ([N-14]), and a
    # redacted dump would make this assertion vacuous.
    dump = JSON.generate(@store.inner.all.map(&:to_h))
    @issued_secrets.each do |secret|
      fail_step(index, 'a raw verifier reached the store ([N-14])') if dump.include?(secret)
    end
    @device_ids.each do |device_id|
      fail_step(index, 'a raw device identifier reached the store ([N-14])') if dump.include?(device_id)
    end
  end

  def expect_revoked(expect, actual, index)
    return unless expect && expect.key?('revoked')
    return if actual == expect['revoked']

    fail_step(index, "expected #{expect['revoked']} revoked, got #{actual}")
  end

  def resolve_token(step, index)
    ref = step['token'] || {}
    return ref['literal'] if ref.key?('literal')

    fail_step(index, 'step has no token reference') unless ref.key?('ref')
    bound = @bindings.fetch(ref['ref']) { fail_step(index, "unknown binding #{ref['ref'].inspect}") }
    return bound.token if ref['forge'].nil?

    parts = bound.token.split('.')
    case ref['forge']
    when 'verifier' then parts[3] = FORGED_VERIFIER
    when 'unknownKid' then parts[1] = 'zz'
    when 'unknownSelector' then parts[2] = FORGED_SELECTOR
    else fail_step(index, "unknown forge #{ref['forge'].inspect}")
    end
    parts.join('.')
  end

  # Absence and the empty string are different values ([N-25]), so a missing
  # key must not collapse into "".
  def device_of(step)
    return LONE_SURROGATE if step['deviceIdKind'] == 'lone-surrogate'

    step['deviceId']
  end

  def check_success(result, expect, index)
    return if expect.nil?

    if expect.key?('generation') && result.generation != expect['generation']
      fail_step(index, "expected generation #{expect['generation']}, got #{result.generation}")
    end
    if expect.key?('kid') && (kid = result.token.split('.')[1]) != expect['kid']
      fail_step(index, "expected kid #{expect['kid']}, got #{kid}")
    end
    if expect.key?('sameFamilyAs') && result.family_id != @bindings.fetch(expect['sameFamilyAs']).family_id
      fail_step(index, 'family_id changed across rotation')
    end
    if expect.key?('sameExpiresAtAs')
      other = @bindings.fetch(expect['sameExpiresAtAs']).expires_at
      fail_step(index, "absolute deadline moved: #{other} -> #{result.expires_at}") if result.expires_at != other
    end
    return unless expect['idleEqualsExpires'] && result.idle_expires_at != result.expires_at

    fail_step(index, "idle_expires_at #{result.idle_expires_at} should be clamped to #{result.expires_at}")
  end

  def bind(step, result)
    @bindings[step['bind']] = TokenBinding.new(result.token, result.family_id, result.expires_at) if step['bind']
    @issued_secrets << result.token.split('.')[3]
  end

  def fail_step(index, message)
    requirements = (@scenario['requirements'] || []).join(', ')
    raise SCENARIO_FAILURE, "[#{@scenario['id']}] step #{index} (#{requirements}): #{message}"
  end
end

class BehaviorTest < Minitest::Test
  VECTORS = BehaviorRunner.load_vectors

  def test_spec_version_matches_the_published_vectors
    assert_equal VECTORS['spec_version'], NebulaToken::SPEC_VERSION
  end

  def test_every_published_scenario_is_executed_or_reported_as_skipped
    outcome = BehaviorRunner.new(VECTORS).run_all

    # [N-48]: a runner that silently iterated nothing must not report success.
    refute_empty outcome.executed, 'no scenario was executed'
    assert_equal VECTORS['counts']['scenarios'], outcome.executed.length + outcome.skipped.length,
                 'every published scenario must be either executed or explicitly skipped'
    assert_operator outcome.executed.length, :>=, VECTORS['counts']['unconditional'],
                    'every unconditional scenario must be executed'

    # Ruby Strings can hold invalid Unicode, so no scenario is inapplicable here.
    skipped = outcome.skipped.map { |s| "#{s.id} (#{s.condition})" }
    assert_empty skipped, "scenarios skipped: #{skipped.join(', ')}"
  end

  # [N-48] is about counting cases; this is about counting FAILURES. Minitest
  # tallies failures by exact class (`group_by { |r| r.failure.class }`), so a
  # runner that raised a SUBCLASS of Minitest::Assertion would print
  # "0 failures, 0 errors" for a run that diverged from the normative vectors —
  # a green-looking log for a red suite. A published conformance claim rests on
  # that line, so the runner's failure class is asserted, not assumed.
  def test_a_diverging_scenario_is_counted_as_a_failure
    scenario = {
      'id' => 'meta-divergence-probe',
      'requirements' => ['N-48'],
      'steps' => [
        { 'op' => 'issue', 'userId' => 'u1', 'bind' => 'a' },
        # A freshly issued token rotates; demanding REUSE_DETECTED must diverge.
        { 'op' => 'refresh', 'token' => { 'ref' => 'a' }, 'expect' => { 'ok' => false, 'error' => 'REUSE_DETECTED' } }
      ]
    }
    error = assert_raises(Minitest::Assertion) { BehaviorRunner.new(VECTORS).run_scenario(scenario) }
    assert_equal Minitest::Assertion, error.class,
                 'the runner must raise Minitest::Assertion itself: a subclass is tallied as ' \
                 'neither a failure nor an error, so a red run prints "0 failures, 0 errors"'
    assert_includes error.message, 'meta-divergence-probe'
  end

  # One test method per scenario, so a failure names the scenario it came from
  # and each runs against a fresh store and clock.
  VECTORS['scenarios'].each do |scenario|
    define_method("test_scenario_#{scenario['id'].tr('-', '_')}") do
      unless BehaviorRunner.applicable?(scenario)
        skip "runtime does not satisfy condition #{scenario['condition'].inspect}"
      end

      BehaviorRunner.new(VECTORS).run_scenario(scenario)
      # The runner raises on divergence; reaching here is the assertion.
      pass
    end
  end
end
