# frozen_string_literal: true

require 'openssl'
require 'securerandom'

# NEBULA — Opaque Rotating Refresh Tokens.
# Ruby implementation of SPECIFICATION.md (spec version 1).
#
# Standard library only: `openssl` and `securerandom`, both still default gems.
# Deliberately NOT `base64`: it was un-defaulted in Ruby 3.4, so requiring it
# from a gem that does not declare the dependency raises LoadError under Bundler
# on a current Ruby — the library would fail to load at all. Base64url is done
# with pack/unpack below, which is stdlib-free and allocation-cheap.
#
# Ruby >= 3.3. Requirement identifiers in comments ([N-*]) refer to SPECIFICATION.md.
module NebulaToken
  # ── Spec constants (§1) ────────────────────────────────────────────────────
  # Every constant of §1 is exposed as a public named value ([N-4]).

  # Version of SPECIFICATION.md this package implements ([N-52]).
  SPEC_VERSION = 1
  PREFIX = 'nbl'
  SELECTOR_BYTES = 16
  VERIFIER_BYTES = 32
  SELECTOR_CHARS = 22
  VERIFIER_CHARS = 43
  MAX_KID_LENGTH = 64
  MAX_TOKEN_LENGTH = 512
  MIN_PEPPER_LENGTH = 32
  DEFAULT_ABSOLUTE_TTL = 60 * 60 * 24 * 30
  DEFAULT_IDLE_TTL = 60 * 60 * 24 * 7
  DEFAULT_REUSE_GRACE = 0

  # HMAC-SHA-256 output, in lowercase hex characters.
  HASH_HEX_CHARS = 64

  # Anchors are `\A`/`\z`, never `^`/`$`: in Ruby those two are LINE anchors, so
  # `/^[A-Za-z0-9_-]+$/` happily matches "…{verifier}\n" and would accept a token
  # with a trailing newline as well formed ([N-6] rule 4, vector p-24).
  B64URL_RE = /\A[A-Za-z0-9_-]+\z/
  KID_RE = /\A[A-Za-z0-9_-]{1,#{MAX_KID_LENGTH}}\z/
  SELECTOR_RE = /\A[A-Za-z0-9_-]{#{SELECTOR_CHARS}}\z/
  VERIFIER_RE = /\A[A-Za-z0-9_-]{#{VERIFIER_CHARS}}\z/
  HEX64_RE = /\A[0-9a-f]{#{HASH_HEX_CHARS}}\z/

  # Record status ([N-10]). Symbols internally; strings are accepted at the
  # store boundary and normalised, see .normalize_status.
  STATUS_ACTIVE = :active
  STATUS_ROTATED = :rotated
  STATUS_REVOKED = :revoked
  STATUSES = [STATUS_ACTIVE, STATUS_ROTATED, STATUS_REVOKED].freeze
  STATUS_BY_NAME = {
    'active' => STATUS_ACTIVE, 'rotated' => STATUS_ROTATED, 'revoked' => STATUS_REVOKED
  }.freeze

  # Protocol outcomes ([N-38]). Plain strings, so they can be logged, compared
  # and serialised without a mapping table.
  #
  # [N-40]: treat this set as OPEN. A future minor version of the specification
  # may add a code; consumers MUST treat an unrecognised code as a refusal
  # rather than assuming their `case` covers everything. Concretely: give every
  # `case result.error` an `else` branch that denies access.
  module ErrorCode
    MALFORMED = 'MALFORMED'
    UNKNOWN_KID = 'UNKNOWN_KID'
    NOT_FOUND = 'NOT_FOUND'
    VERIFIER_MISMATCH = 'VERIFIER_MISMATCH'
    REUSE_DETECTED = 'REUSE_DETECTED'
    REVOKED = 'REVOKED'
    EXPIRED_ABSOLUTE = 'EXPIRED_ABSOLUTE'
    EXPIRED_IDLE = 'EXPIRED_IDLE'
    DEVICE_MISMATCH = 'DEVICE_MISMATCH'
    CONFLICT = 'CONFLICT'

    # The codes defined by spec version 1. Not a closed set ([N-40]).
    ALL = [
      MALFORMED, UNKNOWN_KID, NOT_FOUND, VERIFIER_MISMATCH, REUSE_DETECTED,
      REVOKED, EXPIRED_ABSOLUTE, EXPIRED_IDLE, DEVICE_MISMATCH, CONFLICT
    ].freeze
  end

  # Raised by {Engine#initialize} and {Engine#issue} for caller mistakes
  # (§5, [N-12]). Subclasses ArgumentError so that existing `rescue ArgumentError`
  # keeps working. Protocol outcomes are NEVER raised ([N-29]).
  class ConfigError < ArgumentError
    def initialize(message)
      super("[NEBULA] #{message}")
    end
  end

  # A parsed wire token. `verifier` holds the raw 32 secret bytes.
  class ParsedToken
    attr_reader :kid, :selector, :verifier

    def initialize(kid, selector, verifier)
      @kid = kid
      @selector = selector
      @verifier = verifier
      freeze
    end

    # [N-14]: the raw verifier must not reach any debug representation — the
    # default Struct/Object inspect would print the live secret into a log.
    def inspect
      "#<NebulaToken::ParsedToken kid=#{@kid.inspect} selector=#{@selector.inspect} verifier=[REDACTED]>"
    end
    alias to_s inspect
  end

  module_function

  # ── Base64url, RFC 4648 §5, unpadded ───────────────────────────────────────

  def b64url_encode(bytes)
    [bytes].pack('m0').tr('+/', '-_').delete('=')
  end

  # Returns the decoded bytes, or nil for anything that is not unpadded
  # base64url. Never raises ([N-8]).
  def b64url_decode(str)
    return nil unless str.is_a?(String) && str.encoding.ascii_compatible?
    return nil unless B64URL_RE.match?(str.b)

    standard = str.b.tr('-_', '+/')
    standard << ('=' * ((4 - (standard.bytesize % 4)) % 4))
    standard.unpack1('m0')
  rescue ArgumentError
    # `m0` is the strict decoder: it rejects lengths that cannot be base64.
    nil
  end

  # UTF-8 bytes of a string, or nil when the value has no UTF-8 encoding.
  #
  # A Ruby String is bytes plus an encoding tag, so it can hold something that
  # is not valid Unicode: `"\xED\xA0\x80"` tagged UTF-8 is the unpaired
  # surrogate that arrives trivially through JSON. [N-11] cannot define a hash
  # for such a value, so this returns nil and the caller decides — a binding
  # failure on the attacker-reachable path, a caller error at issue ([N-12]).
  # Deriving a hash from a replacement character instead would make the same
  # identifier hash differently across languages.
  # A binary-tagged String is bytes, not text, and is decided on the BYTES for
  # the same reason pepper_bytes is: the identical identifier reaches Ruby
  # tagged UTF-8 from JSON and ASCII-8BIT from String#b, File.binread or a
  # socket read, and ASCII-8BIT -> UTF-8 transcoding raises for every byte above
  # 0x7F. Transcoding it would refuse an identifier the other nine ports accept
  # — and in `refresh` that refusal is a sender-binding failure, so it would
  # revoke the whole family where the other nine rotate normally. A String that
  # carries a real text encoding still transcodes, so its UTF-8 encoding is the
  # one [N-11] names.
  def utf8_bytes(value)
    return nil unless value.is_a?(String)

    utf8 =
      if value.encoding == Encoding::UTF_8 || value.encoding == Encoding::BINARY
        value
      else
        value.encode(Encoding::UTF_8)
      end
    bytes = utf8.b
    bytes.dup.force_encoding(Encoding::UTF_8).valid_encoding? ? bytes : nil
  rescue EncodingError
    nil
  end

  # The HMAC key bytes of a pepper, or nil when the pepper has no UTF-8
  # encoding ([N-11]).
  #
  # Decided on the BYTES, not on the String's encoding tag. The other nine
  # ports see a byte string and nothing else, and the same secret reaches Ruby
  # tagged UTF-8 from a JSON file and ASCII-8BIT from File.binread, an ENV var
  # or a KMS client — refusing the second, or transcoding it, would key the
  # HMAC differently in Ruby than everywhere else for one configured value.
  # Bytes that are not valid UTF-8 — "\xED\xA0\x80", the unpaired surrogate a
  # lenient decoder emits — have no UTF-8 encoding at all, so they are refused
  # rather than encoded by substitution (§5, [N-24]).
  def pepper_bytes(value)
    return nil unless value.is_a?(String)
    return nil unless value.b.force_encoding(Encoding::UTF_8).valid_encoding?

    value.b
  end

  # ── Parsing (§2) ───────────────────────────────────────────────────────────

  # Parse a wire token ([N-5]..[N-9]). Total: returns nil for every rejection,
  # and raises for nothing — not for nil, not for a non-string, not for bytes
  # that are invalid in the string's own encoding.
  def parse_token(token)
    return nil unless token.is_a?(String)

    # [N-6] rule 1, in BYTES and before any other parsing work.
    return nil if token.bytesize > MAX_TOKEN_LENGTH

    # A cookie value handed over by Rack can carry arbitrary bytes tagged UTF-8.
    # String#split, Regexp#match? and friends raise ArgumentError ("invalid byte
    # sequence in UTF-8") on such a string, which would turn a one-byte request
    # into an unauthenticated 500 on the refresh endpoint instead of MALFORMED
    # ([N-8]). Non-ASCII-compatible encodings (UTF-16/32) cannot hold a token
    # either, and would raise Encoding::CompatibilityError on the split below.
    return nil unless token.valid_encoding? && token.encoding.ascii_compatible?

    parts = token.split('.', -1)
    return nil unless parts.length == 4 # [N-6] rule 2

    prefix, kid, selector, verifier_b64 = parts
    return nil unless prefix == PREFIX # [N-6] rule 3, case-sensitive

    # [N-6] rules 2/4/5/6 in one pass each. The alphabet is ASCII-only, so the
    # character counts in these patterns are also byte counts ([N-1]); the
    # patterns reject padding, whitespace, '+', '/' and every non-ASCII byte.
    return nil unless KID_RE.match?(kid)
    return nil unless SELECTOR_RE.match?(selector)
    return nil unless VERIFIER_RE.match?(verifier_b64)

    verifier = b64url_decode(verifier_b64)
    return nil if verifier.nil? || verifier.bytesize != VERIFIER_BYTES # [N-6] rule 7

    # [N-7] canonical encoding: a 32-byte value has four distinct 43-character
    # spellings, because the last character carries four significant bits and
    # two unused ones. Only the one that re-encodes to itself is a token.
    return nil unless b64url_encode(verifier) == verifier_b64

    ParsedToken.new(kid, selector, verifier)
  end

  # True iff the value is a well-formed kid per the §2 ABNF ([N-5]).
  def kid?(value)
    value.is_a?(String) && value.encoding.ascii_compatible? && KID_RE.match?(value.b)
  end

  # ── Hashing (§3) ───────────────────────────────────────────────────────────

  # verifier_hash = lowercase hex HMAC-SHA-256(pepper, verifier bytes) ([N-11], [N-13]).
  def hash_verifier(pepper, verifier)
    OpenSSL::HMAC.hexdigest('SHA256', hmac_key(pepper), verifier)
  end

  # device_id_hash = lowercase hex HMAC-SHA-256(pepper, UTF-8 of "device:" + device_id)
  # ([N-11]). No normalisation, trimming or case folding is applied to either input.
  #
  # Raises ConfigError for a device id that has no UTF-8 encoding; callers on the
  # attacker-reachable path must pre-check with .utf8_bytes ([N-12]).
  def hash_device_id(pepper, device_id)
    message = utf8_bytes(device_id)
    raise ConfigError, 'device_id is not valid Unicode (unpaired surrogate)' if message.nil?

    OpenSSL::HMAC.hexdigest('SHA256', hmac_key(pepper), DEVICE_PREFIX + message)
  end

  DEVICE_PREFIX = 'device:'.b.freeze

  def hmac_key(pepper)
    key = pepper_bytes(pepper)
    raise ConfigError, 'pepper must be a String with a UTF-8 encoding' if key.nil?

    key
  end

  # Constant-time comparison of two hex digests ([N-31]).
  #
  # Operands that are not exactly 64 LOWERCASE hex characters compare unequal.
  # The guard is the point: a lenient hex decode stops at the first invalid
  # character and silently compares decoded prefixes, so a stored hash that a
  # CHAR(64) column space-padded, an ETL job upper-cased, or a truncating
  # migration cut short would keep on verifying instead of failing closed.
  # Never raises, whatever it is handed.
  def constant_time_equal_hex(a_hex, b_hex)
    return false unless a_hex.is_a?(String) && b_hex.is_a?(String)

    # Matched through a binary view: a String whose bytes are invalid in its own
    # encoding raises ArgumentError on Regexp#match?, and [N-31] forbids raising.
    return false unless HEX64_RE.match?(a_hex.b) && HEX64_RE.match?(b_hex.b)

    # Both operands are known to be exactly 64 bytes here, so the fixed-length
    # comparison (no hashing round, no early exit) is the right primitive.
    OpenSSL.fixed_length_secure_compare(a_hex.b, b_hex.b)
  end

  # Normalise whatever a store returned for `status` ([N-10]).
  #
  # Every mainstream Ruby store hands back the database String — ActiveRecord,
  # Sequel, pg, Redis and JSON all do — while the engine compares Symbols. A
  # positive match on :active with rotation as the fall-through would then rotate
  # revoked and already-rotated tokens, silently disabling reuse detection. So
  # the mapping is explicit and anything unrecognised (nil, "Active", 5, a
  # column default) becomes :revoked: unknown state must refuse, not rotate.
  def normalize_status(value)
    return value if STATUSES.include?(value)

    STATUS_BY_NAME.fetch(value.to_s, STATUS_REVOKED)
  end

  # Did a compare-and-set apply? ([N-17], [N-18])
  #
  # The store contract returns a boolean, but `docs/STORE.md` §4 also tells an
  # adapter to derive it from the affected-row count its driver reports —
  # `cmd_tuples` on a `PG::Result`, `affected_rows` on Mysql2 — and in Ruby `0`
  # is truthy. A bare `unless @store.mark_rotated(...)` therefore reads a LOST
  # compare-and-set as applied: two concurrent refreshes each mint a successor,
  # the family forks into two independently valid lineages, and no later
  # presentation of either is a replay. Reuse detection is not weakened for that
  # family, it is switched off — which is the entire failure [N-17] exists to
  # close. Ruby is the only one of the ten ports where a count can read as
  # success, so this is a Ruby-side guard, not a change of contract.
  #
  # Anything outside the contract fails closed as "not applied": a spurious
  # CONFLICT revokes nothing and is retryable ([N-35]), a spurious success is
  # unrecoverable.
  def cas_applied?(value)
    case value
    when true, false then value
    when Integer then value.positive?
    else false
    end
  end

  # ── Server-side record (§3) ────────────────────────────────────────────────

  # One row per issued token ([N-10]).
  class TokenRecord
    attr_reader :selector, :verifier_hash, :kid, :family_id, :generation, :user_id,
                :device_id_hash, :created_at, :family_expires_at, :idle_expires_at,
                :status, :rotated_at, :replaced_by_selector

    # rubocop:disable Metrics/ParameterLists
    def initialize(selector:, verifier_hash:, kid:, family_id:, generation:, user_id:,
                   created_at:, family_expires_at:, idle_expires_at:,
                   device_id_hash: nil, status: STATUS_ACTIVE, rotated_at: nil,
                   replaced_by_selector: nil)
      @selector = selector
      @verifier_hash = verifier_hash
      @kid = kid
      @family_id = family_id
      @user_id = user_id
      @device_id_hash = device_id_hash
      @replaced_by_selector = replaced_by_selector
      # [N-2]: timestamps and the generation counter are integers. A store that
      # returns them as strings (the pg gem does, by default) must not silently
      # produce `Integer < String` comparisons deep inside the engine.
      @generation = TokenRecord.integer(generation)
      @created_at = TokenRecord.integer(created_at)
      @family_expires_at = TokenRecord.integer(family_expires_at)
      @idle_expires_at = TokenRecord.integer(idle_expires_at)
      @rotated_at = rotated_at.nil? ? nil : TokenRecord.integer(rotated_at)
      self.status = status
    end
    # rubocop:enable Metrics/ParameterLists

    # Kernel#Integer alone reads "010" as octal and "0x10" as hex; a database
    # column is always base 10.
    def self.integer(value)
      value.is_a?(String) ? Integer(value, 10) : Integer(value)
    end

    # The three fields a store mutates in place; see the CAS contract in §4.
    def status=(value)
      @status = NebulaToken.normalize_status(value)
    end

    attr_writer :rotated_at, :replaced_by_selector

    def active? = @status == STATUS_ACTIVE
    def rotated? = @status == STATUS_ROTATED
    def revoked? = @status == STATUS_REVOKED

    def to_h
      {
        selector: @selector, verifier_hash: @verifier_hash, kid: @kid,
        family_id: @family_id, generation: @generation, user_id: @user_id,
        device_id_hash: @device_id_hash, created_at: @created_at,
        family_expires_at: @family_expires_at, idle_expires_at: @idle_expires_at,
        status: @status, rotated_at: @rotated_at, replaced_by_selector: @replaced_by_selector
      }
    end

    def dup_record
      TokenRecord.new(**to_h)
    end

    # [N-14]/[N-46]: no secret-derived material in a debug representation.
    def inspect
      "#<NebulaToken::TokenRecord selector=#{@selector.inspect} kid=#{@kid.inspect} " \
        "family_id=#{@family_id.inspect} user_id=#{@user_id.inspect} generation=#{@generation} " \
        "status=#{@status.inspect} verifier_hash=[REDACTED] device_id_hash=[REDACTED]>"
    end
    alias to_s inspect
  end

  # ── Store contract (§4) ────────────────────────────────────────────────────

  # The six-method storage contract ([N-16]). Ruby stores are duck-typed, so
  # including this module is optional; it documents the contract and turns a
  # forgotten method into a clear NotImplementedError instead of NoMethodError.
  #
  # Two failure channels ([N-20]): protocol outcomes are the return values
  # below; infrastructure failures (connection lost, timeout, constraint
  # violation) MUST be raised. An exception propagates out of the engine and is
  # never converted into a RefreshResult, so the caller always fails closed.
  module RefreshTokenStore
    def find_by_selector(_selector)
      raise NotImplementedError, 'find_by_selector(selector) -> TokenRecord | nil'
    end

    def insert(_record)
      raise NotImplementedError, 'insert(record) -> void'
    end

    # Compare-and-set ([N-17]). Apply the rotation write **only if** the stored
    # record's status is still `from_status`, and return whether it was applied:
    #
    #   UPDATE … SET status='rotated', rotated_at=$2, replaced_by_selector=$3
    #    WHERE selector=$1 AND status=$4   -- and return cmd_tuples == 1
    #
    # Returning true unconditionally is non-conforming: it re-opens the race in
    # which two concurrent refreshes both mint a successor and fork the family.
    def mark_rotated(_selector, _from_status, _rotated_at, _replaced_by_selector)
      raise NotImplementedError, 'mark_rotated(selector, from_status, rotated_at, replaced_by_selector) -> bool'
    end

    # Compare-and-set ([N-18]): revoke only if still active; return whether it did.
    def revoke_if_active(_selector)
      raise NotImplementedError, 'revoke_if_active(selector) -> bool'
    end

    # Revoke every record of the family; return how many changed ([N-19]).
    def revoke_family(_family_id)
      raise NotImplementedError, 'revoke_family(family_id) -> Integer'
    end

    # Revoke every record of the user; return how many changed ([N-19]).
    def revoke_user(_user_id)
      raise NotImplementedError, 'revoke_user(user_id) -> Integer'
    end
  end

  # Reference store ([N-21]).
  #
  # Guarded by a mutex, so the compare-and-set methods are atomic under the
  # threaded request concurrency of Puma, Falcon or Sidekiq.
  #
  # NOT FOR PRODUCTION: state is per-process and lost on restart, so reuse
  # detection does not survive a deploy and does not work behind more than one
  # instance. Implement the six methods over your database instead — start from
  # examples/pg_store.rb, schema in docs/STORE.md.
  class MemoryRefreshTokenStore
    include RefreshTokenStore

    def initialize
      @rows = {}
      @mutex = Mutex.new
    end

    def find_by_selector(selector)
      @mutex.synchronize { @rows[selector]&.dup_record }
    end

    def insert(record)
      @mutex.synchronize do
        if @rows.key?(record.selector)
          # An infrastructure failure, not a protocol outcome ([N-20]): mirrors
          # the primary-key violation a real store would raise.
          raise "[NEBULA] duplicate selector #{record.selector}"
        end

        @rows[record.selector] = record.dup_record
      end
      nil
    end

    def mark_rotated(selector, from_status, rotated_at, replaced_by_selector)
      want = NebulaToken.normalize_status(from_status)
      @mutex.synchronize do
        row = @rows[selector]
        next false if row.nil? || row.status != want

        row.status = STATUS_ROTATED
        row.rotated_at = rotated_at
        row.replaced_by_selector = replaced_by_selector
        true
      end
    end

    def revoke_if_active(selector)
      @mutex.synchronize do
        row = @rows[selector]
        next false unless row&.active?

        row.status = STATUS_REVOKED
        true
      end
    end

    def revoke_family(family_id)
      revoke_where { |row| row.family_id == family_id }
    end

    def revoke_user(user_id)
      revoke_where { |row| row.user_id == user_id }
    end

    # Test helper: every record currently stored. Not part of the store contract.
    def all
      @mutex.synchronize { @rows.values.map(&:dup_record) }
    end

    # Operational helper: drop records whose family deadline has passed. Nothing
    # may be deleted before it ([N-15]) — rotated rows ARE the reuse detector.
    def delete_expired(now)
      @mutex.synchronize do
        expired = @rows.select { |_, row| now >= row.family_expires_at }
        expired.each_key { |selector| @rows.delete(selector) }
        expired.size
      end
    end

    private

    def revoke_where
      @mutex.synchronize do
        @rows.each_value.count do |row|
          next false if row.revoked? || !yield(row)

          row.status = STATUS_REVOKED
          true
        end
      end
    end
  end

  # ── Results (§6) ───────────────────────────────────────────────────────────

  # Result of {Engine#issue}. Every timestamp is integer unix seconds ([N-2]).
  class IssueResult
    attr_reader :token, :user_id, :family_id, :generation, :expires_at, :idle_expires_at

    def initialize(token:, user_id:, family_id:, generation:, expires_at:, idle_expires_at:)
      @token = token
      @user_id = user_id
      @family_id = family_id
      @generation = generation
      @expires_at = expires_at
      @idle_expires_at = idle_expires_at
      freeze
    end

    # [N-14]: the token embeds the raw verifier, so it must never reach a debug
    # representation — `p issued` or `"#{issued}"` in a controller would
    # otherwise write a live credential into the log.
    def inspect
      "#<NebulaToken::IssueResult token=[REDACTED] user_id=#{@user_id.inspect} " \
        "family_id=#{@family_id.inspect} generation=#{@generation} " \
        "expires_at=#{@expires_at} idle_expires_at=#{@idle_expires_at}>"
    end
    alias to_s inspect
  end

  # Result of {Engine#refresh} ([N-29]: outcomes are values, never exceptions).
  #
  # `user_id` and `family_id` are populated whenever the engine resolved a
  # record — every code except MALFORMED, UNKNOWN_KID and NOT_FOUND — so a
  # REUSE_DETECTED or DEVICE_MISMATCH event can be attributed to a session
  # without a second lookup of a token you were told never to log ([N-39]).
  class RefreshResult
    attr_reader :token, :user_id, :family_id, :generation, :expires_at, :idle_expires_at, :error

    # rubocop:disable Metrics/ParameterLists
    def initialize(ok:, token: nil, user_id: nil, family_id: nil, generation: nil,
                   expires_at: nil, idle_expires_at: nil, error: nil)
      @ok = ok
      @token = token
      @user_id = user_id
      @family_id = family_id
      @generation = generation
      @expires_at = expires_at
      @idle_expires_at = idle_expires_at
      @error = error
      freeze
    end
    # rubocop:enable Metrics/ParameterLists

    def ok? = @ok

    def self.success(token:, user_id:, family_id:, generation:, expires_at:, idle_expires_at:)
      new(ok: true, token: token, user_id: user_id, family_id: family_id,
          generation: generation, expires_at: expires_at, idle_expires_at: idle_expires_at)
    end

    # `record` is nil exactly when nothing was resolved ([N-39]).
    def self.failure(error, record = nil)
      new(ok: false, error: error, user_id: record&.user_id, family_id: record&.family_id)
    end

    # [N-14], as for IssueResult.
    def inspect
      "#<NebulaToken::RefreshResult ok=#{@ok} error=#{@error.inspect} " \
        "user_id=#{@user_id.inspect} family_id=#{@family_id.inspect} " \
        "generation=#{@generation.inspect} token=#{@token.nil? ? 'nil' : '[REDACTED]'}>"
    end
    alias to_s inspect
  end

  # Result of {Engine#revoke_token} ([N-36]).
  #
  # On a failure, `user_id` and `family_id` are populated whenever the engine
  # resolved a record, exactly as in {RefreshResult} — [N-39] governs every
  # failure result, not `refresh` alone. revoke_token resolves its record
  # before proving the verifier, so a VERIFIER_MISMATCH there is attributable
  # and carries both; MALFORMED, UNKNOWN_KID and NOT_FOUND never do.
  class RevokeResult
    attr_reader :user_id, :family_id, :revoked, :error

    def initialize(ok:, user_id: nil, family_id: nil, revoked: 0, error: nil)
      @ok = ok
      @user_id = user_id
      @family_id = family_id
      @revoked = revoked
      @error = error
      freeze
    end

    def ok? = @ok

    def self.success(user_id:, family_id:, revoked:)
      new(ok: true, user_id: user_id, family_id: family_id, revoked: revoked)
    end

    # `record` is nil exactly when nothing was resolved ([N-39]).
    def self.failure(error, record = nil)
      new(ok: false, error: error, user_id: record&.user_id, family_id: record&.family_id)
    end
  end

  # ── Engine (§5, §6) ────────────────────────────────────────────────────────

  class Engine
    # @param peppers [Hash{String=>String}] kid → secret, each >= MIN_PEPPER_LENGTH
    #   BYTES; see [N-23] on entropy — the floor is against misconfiguration, not
    #   a sufficient condition for security.
    # @param active_kid [String] kid used for newly minted tokens.
    # @param store [#find_by_selector] the six-method store ([N-16]).
    # @param clock [#call] injectable "now", integer unix seconds ([N-3]).
    # rubocop:disable Metrics/ParameterLists
    def initialize(peppers:, active_kid:, store:,
                   absolute_ttl_seconds: DEFAULT_ABSOLUTE_TTL,
                   idle_ttl_seconds: DEFAULT_IDLE_TTL,
                   reuse_grace_seconds: DEFAULT_REUSE_GRACE,
                   clock: nil)
      @peppers = copy_peppers(peppers)
      unless @peppers.key?(active_kid)
        raise ConfigError, "active_kid #{active_kid.inspect} not present in peppers"
      end

      @active_kid = active_kid
      @store = store
      @absolute_ttl = positive_seconds(absolute_ttl_seconds, 'absolute_ttl_seconds')
      @idle_ttl = positive_seconds(idle_ttl_seconds, 'idle_ttl_seconds')
      @reuse_grace = non_negative_seconds(reuse_grace_seconds, 'reuse_grace_seconds')
      @clock = clock || -> { Time.now.to_i }
      raise ConfigError, 'clock must respond to #call' unless @clock.respond_to?(:call)
    end
    # rubocop:enable Metrics/ParameterLists

    # [N-46]: a pepper is an HMAC key and MUST NOT be logged. The default
    # Object#inspect prints every instance variable, so `p engine`, `pp engine`,
    # `Rails.logger.debug engine` or an error page that dumps ivars would write
    # the entire pepper map into a log in plain text. The kid names are public
    # ([N-45] treats them as routing metadata), the secrets never are.
    def inspect
      "#<NebulaToken::Engine active_kid=#{@active_kid.inspect} kids=#{@peppers.keys.inspect} " \
        "peppers=[REDACTED] absolute_ttl=#{@absolute_ttl} idle_ttl=#{@idle_ttl} " \
        "reuse_grace=#{@reuse_grace} store=#{@store.class}>"
    end
    alias to_s inspect

    # Issue the first token of a new family ([N-25]). Call at login.
    #
    # `device_id` is optional sender binding; nil (absent) and "" (a real,
    # bound, empty identifier) are different values and stay different ([N-25]).
    def issue(user_id, device_id = nil)
      # [N-12]: at issue the device id comes from the application, so an
      # unencodable one is a caller error on the native channel — surfacing the
      # defect here rather than minting a binding nothing can ever satisfy.
      if !device_id.nil? && NebulaToken.utf8_bytes(device_id).nil?
        raise ConfigError, 'device_id is not valid Unicode (unpaired surrogate)'
      end

      now = @clock.call
      family_id = SecureRandom.hex(16)
      family_expires_at = now + @absolute_ttl
      device_hash = device_id.nil? ? nil : NebulaToken.hash_device_id(active_pepper, device_id)
      token, record = mint(user_id, family_id, 0, device_hash, family_expires_at, now)

      # [N-25] step 3: if the insert fails the exception propagates and no token
      # is returned — never hand back a credential for state that was not written.
      @store.insert(record)

      IssueResult.new(token: token, user_id: user_id, family_id: family_id, generation: 0,
                      expires_at: family_expires_at, idle_expires_at: record.idle_expires_at)
    end

    # Exchange a refresh token for its successor.
    #
    # The check order of [N-26] is normative and observable — it fixes which
    # error wins when several conditions hold at once — so the numbered steps
    # below must not be reordered.
    def refresh(token, device_id = nil)
      parsed = NebulaToken.parse_token(token) # 1
      return RefreshResult.failure(ErrorCode::MALFORMED) if parsed.nil?

      return RefreshResult.failure(ErrorCode::UNKNOWN_KID) unless @peppers.key?(parsed.kid) # 2

      record = @store.find_by_selector(parsed.selector) # 3
      return RefreshResult.failure(ErrorCode::NOT_FOUND) if record.nil?

      # 4. Verifier proof against the pepper of the RECORD's kid, not the active
      # one; absent means the pepper was retired since the record was written.
      record_pepper = @peppers[record.kid]
      return RefreshResult.failure(ErrorCode::UNKNOWN_KID) if record_pepper.nil? # [N-27]

      presented = NebulaToken.hash_verifier(record_pepper, parsed.verifier)
      unless NebulaToken.constant_time_equal_hex(presented, record.verifier_hash)
        # [N-28]: no family revocation here. Otherwise knowledge of a selector
        # alone — a value this specification says is safe to index and log —
        # would let anyone destroy a session.
        return RefreshResult.failure(ErrorCode::VERIFIER_MISMATCH, record)
      end

      now = @clock.call

      # Normalised again here, not only inside TokenRecord: a custom store may
      # return any duck-typed row object, and only :active may rotate.
      status = NebulaToken.normalize_status(record.status)

      return handle_reuse(record, record_pepper, device_id, now) if status == STATUS_ROTATED # 5

      # 6. Fail closed: everything that is not exactly :active refuses. Rotation
      # is never the fall-through branch.
      return RefreshResult.failure(ErrorCode::REVOKED, record) unless status == STATUS_ACTIVE

      if now >= record.family_expires_at # 7
        @store.revoke_family(record.family_id)
        return RefreshResult.failure(ErrorCode::EXPIRED_ABSOLUTE, record)
      end

      if now >= record.idle_expires_at # 8
        @store.revoke_family(record.family_id)
        return RefreshResult.failure(ErrorCode::EXPIRED_IDLE, record)
      end

      if !record.device_id_hash.nil? && !device_matches?(record, record_pepper, device_id) # 9
        @store.revoke_family(record.family_id)
        return RefreshResult.failure(ErrorCode::DEVICE_MISMATCH, record)
      end

      rotate(record, device_id, now, STATUS_ACTIVE, now) # 10
    end

    # Revoke the family a token belongs to ([N-36]).
    #
    # Authenticated: steps 1-4 of [N-26] are performed exactly as in #refresh,
    # because the selector is a public lookup key and must not by itself be a
    # capability to terminate a session — that would be an unauthenticated
    # denial of service against an arbitrary user. Succeeds whatever the
    # record's status, so a client can still log out with a token that was
    # already rotated or revoked.
    #
    # It takes no device identifier and performs no sender-binding check
    # ([N-36]): sender binding is not required in order to log out.
    def revoke_token(token)
      parsed = NebulaToken.parse_token(token)
      return RevokeResult.failure(ErrorCode::MALFORMED) if parsed.nil?
      return RevokeResult.failure(ErrorCode::UNKNOWN_KID) unless @peppers.key?(parsed.kid)

      record = @store.find_by_selector(parsed.selector)
      return RevokeResult.failure(ErrorCode::NOT_FOUND) if record.nil?

      record_pepper = @peppers[record.kid]
      return RevokeResult.failure(ErrorCode::UNKNOWN_KID) if record_pepper.nil?

      presented = NebulaToken.hash_verifier(record_pepper, parsed.verifier)
      unless NebulaToken.constant_time_equal_hex(presented, record.verifier_hash)
        # [N-39]: the record was resolved above, so this refusal is attributable.
        # An unauthenticated attempt to terminate somebody's session is exactly
        # the event an operator needs to see, and the selector alone will not
        # identify the victim.
        return RevokeResult.failure(ErrorCode::VERIFIER_MISMATCH, record)
      end

      RevokeResult.success(user_id: record.user_id, family_id: record.family_id,
                           revoked: @store.revoke_family(record.family_id))
    end

    # Revoke a whole family by its server-side identifier ([N-37]). Requires no
    # token; the caller is responsible for authorising it. Idempotent.
    # @return [Integer] records changed.
    def revoke_family(family_id)
      @store.revoke_family(family_id)
    end

    # Revoke every session of a user ([N-37]). Password change, "log out all
    # devices", compromise response. Idempotent.
    # @return [Integer] records changed.
    def revoke_all_for_user(user_id)
      @store.revoke_user(user_id)
    end

    private

    # §6.3 reuse handling.
    def handle_reuse(record, record_pepper, device_id, now)
      # [N-30], all six preconditions. The sixth (now < family_expires_at) is
      # what stops a grace retry from minting a token past the absolute deadline.
      within_grace = @reuse_grace.positive? &&
                     !record.rotated_at.nil? &&
                     (now - record.rotated_at) <= @reuse_grace &&
                     !record.replaced_by_selector.nil? &&
                     now < record.family_expires_at

      if within_grace
        successor = @store.find_by_selector(record.replaced_by_selector)
        if successor && NebulaToken.normalize_status(successor.status) == STATUS_ACTIVE
          if !record.device_id_hash.nil? && !device_matches?(record, record_pepper, device_id)
            @store.revoke_family(record.family_id)
            return RefreshResult.failure(ErrorCode::DEVICE_MISMATCH, record)
          end

          # Compare-and-set: exactly one concurrent retry may consume the unused
          # successor. The loser rotates nothing and reports CONFLICT ([N-30] 2).
          unless NebulaToken.cas_applied?(@store.revoke_if_active(successor.selector))
            return RefreshResult.failure(ErrorCode::CONFLICT, record)
          end

          # Keep the ORIGINAL rotated_at: the window is anchored to the first
          # rotation and cannot be walked forward by repeated retries ([N-30] 3).
          return rotate(record, device_id, now, STATUS_ROTATED, record.rotated_at)
        end
      end

      # Otherwise the presentation is a theft signal.
      @store.revoke_family(record.family_id)
      RefreshResult.failure(ErrorCode::REUSE_DETECTED, record)
    end

    # §6.4 rotation ([N-34]).
    def rotate(record, device_id, now, from_status, rotated_at)
      device_hash = if !record.device_id_hash.nil? && !device_id.nil?
                      # Re-hash with the ACTIVE pepper: migrates the binding
                      # forward across pepper rotation ([N-33] step 4).
                      NebulaToken.hash_device_id(active_pepper, device_id)
                    else
                      record.device_id_hash
                    end

      token, successor = mint(record.user_id, record.family_id, record.generation + 1,
                              device_hash, record.family_expires_at, now)
      @store.insert(successor)

      unless NebulaToken.cas_applied?(@store.mark_rotated(record.selector, from_status,
                                                          rotated_at, successor.selector))
        # [N-34] step 5: a concurrent refresh won the compare-and-set. Clean up
        # the successor we inserted and report a retryable conflict — never a
        # token. Without the CAS both refreshes would mint a successor and the
        # family would fork into two independently valid lineages.
        @store.revoke_if_active(successor.selector)
        return RefreshResult.failure(ErrorCode::CONFLICT, record)
      end

      RefreshResult.success(token: token, user_id: record.user_id, family_id: record.family_id,
                            generation: successor.generation,
                            expires_at: successor.family_expires_at,
                            idle_expires_at: successor.idle_expires_at)
    end

    # §6.4 minting ([N-33]).
    # rubocop:disable Metrics/ParameterLists
    def mint(user_id, family_id, generation, device_id_hash, family_expires_at, now)
      selector = NebulaToken.b64url_encode(SecureRandom.bytes(SELECTOR_BYTES))
      verifier = SecureRandom.bytes(VERIFIER_BYTES)
      record = TokenRecord.new(
        selector: selector,
        verifier_hash: NebulaToken.hash_verifier(active_pepper, verifier),
        kid: @active_kid,
        family_id: family_id,
        generation: generation,
        user_id: user_id,
        device_id_hash: device_id_hash,
        created_at: now,
        family_expires_at: family_expires_at,
        idle_expires_at: [now + @idle_ttl, family_expires_at].min,
        status: STATUS_ACTIVE
      )
      ["#{PREFIX}.#{@active_kid}.#{selector}.#{NebulaToken.b64url_encode(verifier)}", record]
    end
    # rubocop:enable Metrics/ParameterLists

    # [N-32]: hash the presented device id with the RECORD's pepper. A missing
    # identifier where the record is bound fails.
    def device_matches?(record, record_pepper, device_id)
      return false if device_id.nil? || record.device_id_hash.nil?
      # [N-12]: on the attacker-reachable path an unencodable device id is a
      # binding failure, never an exception.
      return false if NebulaToken.utf8_bytes(device_id).nil?

      NebulaToken.constant_time_equal_hex(
        NebulaToken.hash_device_id(record_pepper, device_id), record.device_id_hash
      )
    end

    def active_pepper
      @peppers[@active_kid]
    end

    # [N-24]: copy the configuration. Mutating the caller's Hash afterwards — or
    # the pepper String in place, which Ruby permits and JavaScript does not —
    # must not change engine behaviour.
    def copy_peppers(peppers)
      raise ConfigError, 'peppers must be a Hash of kid => secret' unless peppers.is_a?(Hash)
      raise ConfigError, 'peppers must not be empty' if peppers.empty?

      peppers.each_with_object({}) do |(kid, secret), copy|
        unless NebulaToken.kid?(kid)
          raise ConfigError, "kid #{kid.inspect} must be 1-#{MAX_KID_LENGTH} bytes from [A-Za-z0-9_-]"
        end
        # [N-11]: the HMAC key is the pepper's UTF-8 encoding, so a pepper with
        # no UTF-8 encoding is not a usable key and MUST fail construction
        # (§5, [N-24]) rather than be encoded by substitution. Decided on the
        # bytes — see .pepper_bytes. The message never quotes the secret ([N-14]).
        key = NebulaToken.pepper_bytes(secret)
        if key.nil?
          raise ConfigError, "pepper for kid #{kid.inspect} must be a String with a UTF-8 encoding"
        end
        # Bytes OF THAT ENCODING, not characters ([N-1]): "日" * 11 is 11
        # characters and 33 bytes.
        if key.bytesize < MIN_PEPPER_LENGTH
          raise ConfigError, "pepper for kid #{kid.inspect} must be at least #{MIN_PEPPER_LENGTH} bytes"
        end

        # dup.freeze, not String#-@: interning a secret in the fstring table
        # would keep it alive for the life of the process.
        copy[kid.dup.freeze] = secret.dup.freeze
      end.freeze
    end

    def positive_seconds(value, name)
      raise ConfigError, "#{name} must be a positive Integer" unless value.is_a?(Integer) && value.positive?

      value
    end

    def non_negative_seconds(value, name)
      raise ConfigError, "#{name} must be a non-negative Integer" unless value.is_a?(Integer) && !value.negative?

      value
    end
  end
end
