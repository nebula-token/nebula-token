defmodule NebulaToken.Parsed do
  @moduledoc """
  A parsed wire token (§2) — the result of `NebulaToken.parse_token/1`.

  `verifier` holds the raw 32 secret bytes, so this is a struct with a redacted
  `Inspect` rather than a bare map: a map prints every field, and the first
  `Logger.debug(inspect(parsed))`, crash dump or `IEx` echo that walks one puts
  a live verifier in a log ([N-14], [N-46]). Exactly as with
  `NebulaToken.Engine`'s peppers, only the *debug* rendering is redacted —
  `parsed.verifier` still returns the bytes, so a caller that legitimately needs
  them is unaffected.
  """

  @enforce_keys [:kid, :selector, :verifier]
  # [N-46] keep the secret out of every accidental inspect/1.
  @derive {Inspect, except: [:verifier]}
  defstruct [:kid, :selector, :verifier]

  @type t :: %__MODULE__{
          kid: String.t(),
          selector: String.t(),
          verifier: binary()
        }
end

defmodule NebulaToken do
  @moduledoc """
  NEBULA — Opaque Rotating Refresh Tokens.

  Elixir implementation of `SPECIFICATION.md` (spec version 1): opaque tokens,
  rotation on every use, reuse detection with family revocation, bounded
  lifetimes and optional sender binding — the RFC 9700 refresh-token model.

  `:crypto` + stdlib only. **Requires Elixir >= 1.18 and Erlang/OTP >= 25**: the
  constant-time comparison mandated by [N-31] is `:crypto.hash_equals/2`, which
  OTP introduced in 25. It is used for the verifier proof *and* the device
  binding, so on an older OTP every `NebulaToken.Engine.refresh/3` would raise
  `UndefinedFunctionError` while `issue/3` kept working — a failure mode that
  only shows up in production. `mix.exs` therefore fails the build on OTP < 25.

  This module holds the spec constants ([N-4]) and the four pure primitives:
  `parse_token/1`, `hash_verifier/2`, `hash_device_id/2` and
  `constant_time_equal_hex/2`. The protocol lives in `NebulaToken.Engine`, the
  storage contract in `NebulaToken.Store`.

  Requirement identifiers in comments ([N-*]) refer to `SPECIFICATION.md`.
  """

  # ── Spec constants (§1, [N-4]) ────────────────────────────────────────────

  @spec_version 1
  @prefix "nbl"
  @selector_bytes 16
  @verifier_bytes 32
  @selector_chars 22
  @verifier_chars 43
  @max_kid_length 64
  @max_token_length 512
  @min_pepper_length 32
  @default_absolute_ttl 60 * 60 * 24 * 30
  @default_idle_ttl 60 * 60 * 24 * 7
  @default_reuse_grace 0

  # HMAC-SHA-256 rendered as lowercase hex.
  @hash_hex_chars 64

  @doc "Version of `SPECIFICATION.md` this package implements ([N-52])."
  def spec_version, do: @spec_version
  @doc "Wire prefix. Reserved by the specification ([N-51])."
  def prefix, do: @prefix
  @doc "CSPRNG bytes behind a selector."
  def selector_bytes, do: @selector_bytes
  @doc "CSPRNG bytes behind a verifier."
  def verifier_bytes, do: @verifier_bytes
  @doc "Unpadded base64url characters of a selector."
  def selector_chars, do: @selector_chars
  @doc "Unpadded base64url characters of a verifier."
  def verifier_chars, do: @verifier_chars
  @doc "Maximum `kid` length, in bytes ([N-1])."
  def max_kid_length, do: @max_kid_length
  @doc "Maximum token length, in bytes ([N-1])."
  def max_token_length, do: @max_token_length
  @doc "Minimum pepper length, in **bytes** — never characters or graphemes ([N-1])."
  def min_pepper_length, do: @min_pepper_length
  @doc "Default absolute TTL, seconds."
  def default_absolute_ttl, do: @default_absolute_ttl
  @doc "Default idle TTL, seconds."
  def default_idle_ttl, do: @default_idle_ttl
  @doc "Default reuse grace window, seconds (strict)."
  def default_reuse_grace, do: @default_reuse_grace

  # ── Types ─────────────────────────────────────────────────────────────────

  @type status :: :active | :rotated | :revoked

  @error_codes [
    :MALFORMED,
    :UNKNOWN_KID,
    :NOT_FOUND,
    :VERIFIER_MISMATCH,
    :REUSE_DETECTED,
    :REVOKED,
    :EXPIRED_ABSOLUTE,
    :EXPIRED_IDLE,
    :DEVICE_MISMATCH,
    :CONFLICT
  ]

  @typedoc """
  Protocol outcome ([N-38]).

  [N-40] requires the error type to be open to future additions. Elixir atoms
  are inherently open, and this is the documented policy that stands in for
  Rust's `#[non_exhaustive]`: **a future minor version MAY add a code**, so
  every `case`/`cond` over a failure MUST carry a catch-all clause that treats
  an unrecognised code as a refusal. Matching only the ten codes below without
  a fallback is a forward-compatibility bug, not an exhaustive match.
  """
  @type error_code ::
          :MALFORMED
          | :UNKNOWN_KID
          | :NOT_FOUND
          | :VERIFIER_MISMATCH
          | :REUSE_DETECTED
          | :REVOKED
          | :EXPIRED_ABSOLUTE
          | :EXPIRED_IDLE
          | :DEVICE_MISMATCH
          | :CONFLICT

  @type parsed :: NebulaToken.Parsed.t()

  @doc """
  The ten codes of [N-38], as of spec version 1.

  Exposed for tests and for exhaustiveness checks at the transport boundary;
  see `t:error_code/0` for why consumers must still tolerate an unknown code.
  """
  @spec error_codes() :: [error_code()]
  def error_codes, do: @error_codes

  # ── Parsing (§2) ──────────────────────────────────────────────────────────

  @doc """
  Parse a wire token (§2, [N-5]..[N-9]).

  Total by construction: returns `{:ok, %NebulaToken.Parsed{}}` or `:error` for
  **every** input, including non-binaries, `nil`, invalid UTF-8 and oversized
  strings. It never raises ([N-8]) and is not influenced by locale or case
  folding ([N-9]).

  The success value is a struct rather than a map so that `inspect/1` cannot
  print the raw verifier it carries ([N-14], [N-46]).
  """
  @spec parse_token(term()) :: {:ok, parsed()} | :error
  def parse_token(token) when is_binary(token) do
    # [N-6.1] the byte-length check comes before any other parsing work, so a
    # multi-megabyte input costs one comparison rather than a split.
    if byte_size(token) > @max_token_length do
      :error
    else
      token |> :binary.split(".", [:global]) |> parse_parts()
    end
  end

  def parse_token(_), do: :error

  # The exact-length and prefix rules live in the head, so anything else falls
  # through to the catch-all below: [N-6.2] four non-empty parts, [N-6.3] the
  # case-sensitive literal prefix, [N-6.5] and [N-6.6] the length bounds.
  defp parse_parts([@prefix, kid, selector, verifier_b64])
       when byte_size(kid) in 1..@max_kid_length and
              byte_size(selector) == @selector_chars and
              byte_size(verifier_b64) == @verifier_chars do
    with true <- b64url?(kid),
         true <- b64url?(selector),
         true <- b64url?(verifier_b64),
         {:ok, verifier} <- Base.url_decode64(verifier_b64, padding: false),
         # [N-6.7] exactly 32 bytes.
         true <- byte_size(verifier) == @verifier_bytes,
         # [N-7] canonical encoding: 32 bytes have four 43-character spellings
         # because the last character carries four significant bits and two
         # unused ones. Re-encoding is the cheapest way to admit only one.
         true <- Base.url_encode64(verifier, padding: false) == verifier_b64 do
      # A struct, not a map: %NebulaToken.Parsed{} redacts the raw verifier from
      # inspect/1 ([N-14], [N-46]). Field access is unchanged.
      {:ok, %NebulaToken.Parsed{kid: kid, selector: selector, verifier: verifier}}
    else
      _ -> :error
    end
  end

  defp parse_parts(_), do: :error

  # [N-6.4] the b64url alphabet, scanned byte by byte on purpose.
  #
  # A regex would have to be anchored `\A…\z` and never `^…$`: in PCRE — the
  # engine behind Elixir's `~r//` — `$` also matches immediately before a
  # trailing newline, so `~r/^[A-Za-z0-9_-]+$/` accepts "…{verifier}\n" as
  # well-formed (test vector p-24). A byte scan has no such subtlety, cannot be
  # perturbed by the `unicode`/`ucp` modifiers, and cannot raise on invalid
  # UTF-8 ([N-8]).
  defp b64url?(<<>>), do: true

  defp b64url?(<<c, rest::binary>>)
       when c in ?A..?Z or c in ?a..?z or c in ?0..?9 or c == ?- or c == ?_,
       do: b64url?(rest)

  defp b64url?(_), do: false

  @doc "True iff `kid` matches the `kid` production of §2 ([N-5])."
  @spec valid_kid?(term()) :: boolean()
  def valid_kid?(kid) when is_binary(kid),
    do: byte_size(kid) in 1..@max_kid_length and b64url?(kid)

  def valid_kid?(_), do: false

  # ── Keyed hashing (§3, §8) ────────────────────────────────────────────────

  @doc """
  `verifier_hash` = lowercase hex `HMAC-SHA-256(pepper, verifier)` ([N-11], [N-13]).

  The HMAC key is the pepper's UTF-8 encoding, which on the BEAM is simply the
  binary itself — Elixir strings are UTF-8 binaries, so no transcoding step can
  silently disagree with the other implementations.
  """
  @spec hash_verifier(String.t(), binary()) :: String.t()
  def hash_verifier(pepper, verifier) when is_binary(pepper) and is_binary(verifier) do
    :crypto.mac(:hmac, :sha256, pepper, verifier) |> Base.encode16(case: :lower)
  end

  @doc """
  `device_id_hash` = lowercase hex `HMAC-SHA-256(pepper, "device:" <> device_id)`
  ([N-11], [N-13]).

  No normalisation, trimming or case folding is applied to either operand, and
  the `"device:"` prefix is literal — a device id that itself contains a colon
  is not escaped (vector `dh-06`).

  Raises `ArgumentError` when `device_id` is not valid UTF-8: such a value has
  no encoding, so [N-11] cannot define a hash for it. Callers on the
  attacker-reachable path must pre-check rather than rescue ([N-12]); the engine
  does exactly that.
  """
  @spec hash_device_id(String.t(), String.t()) :: String.t()
  def hash_device_id(pepper, device_id) when is_binary(pepper) and is_binary(device_id) do
    if String.valid?(device_id) do
      :crypto.mac(:hmac, :sha256, pepper, "device:" <> device_id) |> Base.encode16(case: :lower)
    else
      # The message deliberately does not echo the value ([N-14], [N-46]).
      raise ArgumentError, "[NEBULA] device_id is not valid UTF-8 and has no defined hash ([N-12])"
    end
  end

  @doc """
  Constant-time comparison of two hex digests ([N-31]).

  Operands that are not **exactly 64 lowercase hexadecimal characters** compare
  unequal. The guard is the point of the function: a lenient decode
  (`Base.decode16(case: :mixed)`, say) stops at the first invalid character and
  compares prefixes, so a stored hash that an ETL job upper-cased, a `CHAR`
  column space-padded, or a truncating migration cut short would keep verifying
  instead of failing closed.

  Never raises, whatever it is handed.
  """
  @spec constant_time_equal_hex(term(), term()) :: boolean()
  def constant_time_equal_hex(a_hex, b_hex) when is_binary(a_hex) and is_binary(b_hex) do
    # Both operands are known to be the same length here, which is what
    # :crypto.hash_equals/2 requires; comparing the hex text directly avoids a
    # decode step that could reintroduce leniency.
    lower_hex_64?(a_hex) and lower_hex_64?(b_hex) and :crypto.hash_equals(a_hex, b_hex)
  end

  def constant_time_equal_hex(_, _), do: false

  defp lower_hex_64?(bin), do: byte_size(bin) == @hash_hex_chars and lower_hex?(bin)

  defp lower_hex?(<<>>), do: true
  defp lower_hex?(<<c, rest::binary>>) when c in ?0..?9 or c in ?a..?f, do: lower_hex?(rest)
  defp lower_hex?(_), do: false
end

defmodule NebulaToken.Record do
  @moduledoc """
  Server-side record — one row per issued token ([N-10]).

  Holds only hashes: the raw verifier and the raw device identifier never reach
  this struct, so `inspect/1` on it cannot leak a secret ([N-14], [N-46]).

  Timestamps are Unix **seconds** as plain integers ([N-2]); BEAM integers are
  arbitrary precision, comfortably exceeding the required signed 64 bits.

  [N-15] retention: a record MUST survive, with its `status` and
  `replaced_by_selector` intact, until at least `family_expires_at`. Deleting
  rotated rows early turns every replay from `:REUSE_DETECTED` into
  `:NOT_FOUND`, which disables reuse detection entirely.
  """

  @enforce_keys [
    :selector,
    :verifier_hash,
    :kid,
    :family_id,
    :generation,
    :user_id,
    :created_at,
    :family_expires_at,
    :idle_expires_at
  ]
  defstruct [
    :selector,
    :verifier_hash,
    :kid,
    :family_id,
    :generation,
    :user_id,
    :device_id_hash,
    :created_at,
    :family_expires_at,
    :idle_expires_at,
    :rotated_at,
    :replaced_by_selector,
    status: :active
  ]

  @type t :: %__MODULE__{
          selector: String.t(),
          verifier_hash: String.t(),
          kid: String.t(),
          family_id: String.t(),
          generation: non_neg_integer(),
          user_id: String.t(),
          device_id_hash: String.t() | nil,
          created_at: integer(),
          family_expires_at: integer(),
          idle_expires_at: integer(),
          status: NebulaToken.status(),
          rotated_at: integer() | nil,
          replaced_by_selector: String.t() | nil
        }
end

defmodule NebulaToken.Failure do
  @moduledoc """
  A protocol outcome that is not a success ([N-38], [N-39]).

  `user_id` and `family_id` are populated whenever the engine resolved a record
  — every code except `:MALFORMED`, `:UNKNOWN_KID` and `:NOT_FOUND` — so that a
  `:REUSE_DETECTED` or `:DEVICE_MISMATCH` event can be attributed to a session
  without a second lookup of a token you were told never to log.

  Match on the struct's `:code`; see `t:NebulaToken.error_code/0` for why a
  catch-all clause is mandatory:

      case NebulaToken.Engine.refresh(engine, token, device_id) do
        {:ok, result} -> {:ok, result.token}
        {:error, %NebulaToken.Failure{code: :REUSE_DETECTED} = f} -> alert(f.user_id, f.family_id)
        {:error, %NebulaToken.Failure{}} -> :require_login
      end
  """

  @enforce_keys [:code]
  defstruct [:code, :user_id, :family_id]

  @type t :: %__MODULE__{
          code: NebulaToken.error_code(),
          user_id: String.t() | nil,
          family_id: String.t() | nil
        }
end

defmodule NebulaToken.TokenResult do
  @moduledoc """
  Result of `NebulaToken.Engine.issue/3` and of a successful
  `NebulaToken.Engine.refresh/3`. Timestamps are Unix seconds ([N-2]).

  `token` is the live credential, which is why this is a struct with a redacted
  `Inspect` and not a bare map ([N-14], [N-46]): a map prints every field, so
  one `Logger.info(inspect(result))`, one crash dump, or one `IEx` echo hands
  the token to whoever reads the log — and unlike the verifier, that value is
  directly replayable.

  Only the *debug* rendering is redacted. `result.token` still returns the
  token, so the handler that sends it to the client is unaffected, and
  `Map.from_struct/1` gives a plain map for a serialiser that needs one.
  """

  @enforce_keys [:token, :user_id, :family_id, :generation, :expires_at, :idle_expires_at]
  # [N-46] as with NebulaToken.Engine's peppers: keep the secret out of every
  # accidental inspect/1.
  @derive {Inspect, except: [:token]}
  defstruct [:token, :user_id, :family_id, :generation, :expires_at, :idle_expires_at]

  @type t :: %__MODULE__{
          token: String.t(),
          user_id: String.t(),
          family_id: String.t(),
          generation: non_neg_integer(),
          expires_at: integer(),
          idle_expires_at: integer()
        }
end

defmodule NebulaToken.StoreError do
  @moduledoc """
  Infrastructure failure from the storage layer ([N-20]).

  Raised by `NebulaToken.Engine` when a `NebulaToken.Store` callback answers
  `{:error, reason}` — unreachable database, timeout, constraint violation — or
  returns something outside its contract.

  This is the *second* failure channel, deliberately distinct from
  `NebulaToken.Failure`. Protocol outcomes are return values; an infrastructure
  failure must never be laundered into one, because the caller would then act on
  a verdict the store never confirmed. Letting it raise is what makes every
  engine operation fail closed: no token is returned for state that was not
  written, and no revocation is reported that did not happen.
  """

  defexception [:operation, :reason]

  @type t :: %__MODULE__{operation: atom(), reason: term()}

  @impl true
  def exception({operation, reason}), do: %__MODULE__{operation: operation, reason: reason}

  @impl true
  def message(%__MODULE__{operation: operation, reason: reason}) do
    "[NEBULA] store operation #{inspect(operation)} failed: #{inspect(reason)}"
  end
end

defmodule NebulaToken.Store do
  @moduledoc """
  Storage contract ([N-16]) — exactly six callbacks, implement over Postgres,
  Redis, DynamoDB, whatever you run.

  Every callback takes as its first argument the opaque handle passed to
  `NebulaToken.Engine.new/1` as `:store` (an `Agent` pid, a `Postgrex` pool
  name, an `Ecto.Repo`, a tuple of those). The module implementing this
  behaviour is the `:store_mod` option — see `NebulaToken.Engine` for why
  forgetting it is a production incident rather than a typo.

  ## Two failure channels ([N-20])

  Protocol outcomes are the `{:ok, _}` payloads: "no such record", "the
  compare-and-set did not apply", "three rows changed". Infrastructure failures
  are `{:error, reason}`; the engine turns those into a raised
  `NebulaToken.StoreError` so they can never be mistaken for a protocol outcome.
  A callback MUST NOT swallow a database error and answer `{:ok, false}` or
  `{:ok, 0}` — that reports a state transition that did not happen.

  ## Atomicity ([N-22])

  A store SHOULD execute the rotation write pair — `c:insert/2` of the successor
  followed by `c:mark_rotated/5` of the predecessor — inside one transaction.
  Where it cannot, the engine's compensation in [N-34] step 5 applies: the
  orphan successor is revoked and the caller gets `:CONFLICT`.
  """

  alias NebulaToken.Record

  @doc "Look a record up by its selector — the only token-derived value that may be indexed ([N-45])."
  @callback find_by_selector(store :: term(), selector :: String.t()) ::
              {:ok, Record.t() | nil} | {:error, term()}

  @doc "Persist a freshly minted record. A duplicate selector MUST NOT overwrite an existing row."
  @callback insert(store :: term(), record :: Record.t()) :: :ok | {:error, term()}

  @doc """
  Compare-and-set ([N-17]). Apply the rotation write **if and only if** the
  stored record's status is still `from_status`, and report whether it applied:

      UPDATE refresh_tokens
         SET status = 'rotated', rotated_at = $3, replaced_by_selector = $4
       WHERE selector = $1 AND status = $2

  returning `{:ok, num_rows == 1}`.

  Answering `{:ok, true}` unconditionally is non-conforming: it re-opens the
  race in which two concurrent refreshes each mint a successor and the family
  forks into two independently valid lineages, defeating reuse detection.
  """
  @callback mark_rotated(
              store :: term(),
              selector :: String.t(),
              from_status :: NebulaToken.status(),
              rotated_at :: integer(),
              replaced_by_selector :: String.t()
            ) :: {:ok, boolean()} | {:error, term()}

  @doc "Compare-and-set ([N-18]): set `status = :revoked` iff it is currently `:active`, and report whether it did."
  @callback revoke_if_active(store :: term(), selector :: String.t()) ::
              {:ok, boolean()} | {:error, term()}

  @doc "Revoke every record of the family; return how many rows changed. Idempotent ([N-19])."
  @callback revoke_family(store :: term(), family_id :: String.t()) ::
              {:ok, non_neg_integer()} | {:error, term()}

  @doc "Revoke every record of the user; return how many rows changed. Idempotent ([N-19])."
  @callback revoke_user(store :: term(), user_id :: String.t()) ::
              {:ok, non_neg_integer()} | {:error, term()}
end

defmodule NebulaToken.MemoryStore do
  @moduledoc """
  Reference in-memory store ([N-21]) — an `Agent` holding `selector => record`.

  The `Agent` serialises every callback into one process, so the two
  compare-and-set callbacks are atomic with respect to each other for all
  processes on the node without further synchronisation: `Agent.get_and_update/2`
  reads and writes inside a single message.

  **NOT FOR PRODUCTION.** State is per-process and lost on restart, so reuse
  detection does not survive a deploy and does not work across more than one
  node — the two situations in which you most need it. Implement
  `NebulaToken.Store` over your database instead and pass it as `:store_mod`;
  start from `examples/postgrex_store.ex` (schema in `docs/STORE.md`).
  """

  @behaviour NebulaToken.Store

  alias NebulaToken.Record

  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts \\ []), do: Agent.start_link(fn -> %{} end, opts)

  @impl true
  def find_by_selector(agent, selector), do: {:ok, Agent.get(agent, &Map.get(&1, selector))}

  @impl true
  def insert(agent, %Record{} = record) do
    Agent.get_and_update(agent, fn rows ->
      if Map.has_key?(rows, record.selector) do
        # Never overwrite: a selector collision would silently destroy a live
        # session, and it is a bug worth surfacing rather than absorbing.
        {{:error, {:duplicate_selector, record.selector}}, rows}
      else
        {:ok, Map.put(rows, record.selector, record)}
      end
    end)
  end

  @impl true
  def mark_rotated(agent, selector, from_status, rotated_at, replaced_by_selector) do
    Agent.get_and_update(agent, fn rows ->
      case rows do
        %{^selector => %Record{status: ^from_status} = record} ->
          rotated = %{
            record
            | status: :rotated,
              rotated_at: rotated_at,
              replaced_by_selector: replaced_by_selector
          }

          {{:ok, true}, Map.put(rows, selector, rotated)}

        _ ->
          {{:ok, false}, rows}
      end
    end)
  end

  @impl true
  def revoke_if_active(agent, selector) do
    Agent.get_and_update(agent, fn rows ->
      case rows do
        %{^selector => %Record{status: :active} = record} ->
          {{:ok, true}, Map.put(rows, selector, %{record | status: :revoked})}

        _ ->
          {{:ok, false}, rows}
      end
    end)
  end

  @impl true
  def revoke_family(agent, family_id), do: revoke_where(agent, &(&1.family_id == family_id))

  @impl true
  def revoke_user(agent, user_id), do: revoke_where(agent, &(&1.user_id == user_id))

  # Counts only the rows it actually changed, so a repeat call returns 0 ([N-19]).
  defp revoke_where(agent, pred) do
    Agent.get_and_update(agent, fn rows ->
      {updated, changed} =
        Enum.reduce(rows, {rows, 0}, fn {selector, record}, {acc, n} ->
          if pred.(record) and record.status != :revoked do
            {Map.put(acc, selector, %{record | status: :revoked}), n + 1}
          else
            {acc, n}
          end
        end)

      {{:ok, changed}, updated}
    end)
  end

  @doc "Test helper: every record currently stored. Not part of the store contract."
  @spec all(Agent.agent()) :: [Record.t()]
  def all(agent), do: Agent.get(agent, &Map.values/1)

  @doc """
  Operational helper: drop records whose family deadline has passed.

  [N-15] permits deletion only once `now >= family_expires_at`; anything earlier
  disables reuse detection.
  """
  @spec delete_expired(Agent.agent(), integer()) :: non_neg_integer()
  def delete_expired(agent, now) do
    Agent.get_and_update(agent, fn rows ->
      {keep, drop} = Enum.split_with(rows, fn {_selector, r} -> now < r.family_expires_at end)
      {length(drop), Map.new(keep)}
    end)
  end
end

defmodule NebulaToken.Engine do
  @moduledoc """
  The NEBULA engine — §5, §6 of `SPECIFICATION.md`.

  A plain immutable struct: build it once (in your Phoenix application
  supervisor, a context module, or `:persistent_term`) and pass it around. All
  state lives in the store.

  ## Wiring a store — read this before shipping

  Two options travel together and **both** matter:

    * `:store_mod` — the module implementing `NebulaToken.Store`. Defaults to
      `NebulaToken.MemoryStore`. Omitting it therefore does not fail: it
      silently routes every call to the in-memory store, and the deployment
      loses every session on restart while reuse detection stops working across
      nodes. Production configurations MUST set it.
    * `:store` — the handle handed back to that module as its first argument
      (an `Agent` pid, a `Postgrex` pool name, an `Ecto.Repo`, …).

  ```elixir
  engine =
    NebulaToken.Engine.new(
      peppers: %{"k1" => System.fetch_env!("NEBULA_PEPPER_K1")},
      active_kid: "k1",
      store_mod: MyApp.RefreshTokenStore,
      store: MyApp.Repo,
      reuse_grace_seconds: 0
    )
  ```

  ## Options (§5)

  | Option | Meaning |
  |---|---|
  | `:peppers` | `%{kid => secret}`. Each kid matches §2's `kid` production; each secret has a UTF-8 encoding ([N-11]) and is at least `NebulaToken.min_pepper_length/0` **bytes of that encoding** ([N-1], [N-23]). |
  | `:active_kid` | The kid newly minted tokens are written under. MUST exist in `:peppers`. |
  | `:store_mod` | Module implementing `NebulaToken.Store`. Defaults to `NebulaToken.MemoryStore`. |
  | `:store` | Handle passed to `:store_mod`. |
  | `:absolute_ttl_seconds` | Positive integer. Default 30 days. |
  | `:idle_ttl_seconds` | Positive integer. Default 7 days. |
  | `:reuse_grace_seconds` | Non-negative integer. Default 0 — read [N-30] before raising it. |
  | `:clock` | 0-arity function returning Unix seconds ([N-3]). |

  Invalid configuration raises `ArgumentError` at construction.

  ## Failure channels

  `refresh/3` returns `{:ok, %NebulaToken.TokenResult{}}` and `revoke_token/2`
  `{:ok, map}`; both refuse with
  `{:error, %NebulaToken.Failure{}}` — protocol outcomes are values, never
  exceptions ([N-29]). A storage failure raises `NebulaToken.StoreError`
  instead, so it can never be mistaken for a verdict ([N-20]).
  """

  alias NebulaToken.{Failure, Record, StoreError, TokenResult}

  # [N-46] the struct carries the peppers; keep them out of crash dumps, Logger
  # metadata and every accidental `inspect(engine)` in a controller.
  @derive {Inspect, except: [:peppers]}
  @enforce_keys [
    :peppers,
    :active_kid,
    :store_mod,
    :store,
    :clock,
    :absolute_ttl,
    :idle_ttl,
    :reuse_grace
  ]
  defstruct [
    :peppers,
    :active_kid,
    :store_mod,
    :store,
    :clock,
    :absolute_ttl,
    :idle_ttl,
    :reuse_grace
  ]

  @type t :: %__MODULE__{
          peppers: %{String.t() => String.t()},
          active_kid: String.t(),
          store_mod: module(),
          store: term(),
          clock: (-> integer()),
          absolute_ttl: pos_integer(),
          idle_ttl: pos_integer(),
          reuse_grace: non_neg_integer()
        }

  @typedoc """
  Result of `issue/3` and of a successful `refresh/3`. Timestamps are Unix
  seconds ([N-2]).

  A `NebulaToken.TokenResult` struct, so that the live token it carries cannot
  reach a debug rendering ([N-14], [N-46]).
  """
  @type token_result :: TokenResult.t()

  @type revoke_result :: %{
          user_id: String.t(),
          family_id: String.t(),
          revoked: non_neg_integer()
        }

  @doc """
  Validate the configuration (§5) and build an engine.

  Raises `ArgumentError` on any violation — a misconfigured pepper is not a
  runtime condition to be handled, it is a deployment that must not start.
  """
  @spec new(keyword()) :: t()
  def new(opts) when is_list(opts) do
    peppers = validate_peppers(Keyword.fetch!(opts, :peppers))
    active_kid = Keyword.fetch!(opts, :active_kid)

    if not is_map_key(peppers, active_kid) do
      raise ArgumentError, "[NEBULA] active_kid #{inspect(active_kid)} not present in peppers"
    end

    %__MODULE__{
      peppers: peppers,
      active_kid: active_kid,
      store_mod: Keyword.get(opts, :store_mod, NebulaToken.MemoryStore),
      store: Keyword.fetch!(opts, :store),
      absolute_ttl:
        integer_option!(opts, :absolute_ttl_seconds, NebulaToken.default_absolute_ttl(), 1),
      idle_ttl: integer_option!(opts, :idle_ttl_seconds, NebulaToken.default_idle_ttl(), 1),
      reuse_grace:
        integer_option!(opts, :reuse_grace_seconds, NebulaToken.default_reuse_grace(), 0),
      clock: Keyword.get(opts, :clock, &default_clock/0)
    }
  end

  @doc """
  Issue the first token of a new family ([N-25]). Call it at login.

  `device_id` is optional. `nil` means "unbound"; `""` is a real binding — on
  the BEAM only `nil` and `false` are falsy, so an empty string can never
  collapse into absence the way it does in languages with truthy strings.

  Raises `ArgumentError` if `device_id` is not valid UTF-8 ([N-12]) and
  `NebulaToken.StoreError` if the insert fails: either way no token is returned
  for state that was not written ([N-20]).
  """
  @spec issue(t(), String.t(), String.t() | nil) :: token_result()
  def issue(%__MODULE__{} = engine, user_id, device_id \\ nil) do
    device_id_hash = issue_device_hash(engine, device_id)
    now = engine.clock.()
    family_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
    family_expires_at = now + engine.absolute_ttl

    {token, record} =
      mint(engine, user_id, family_id, 0, device_id_hash, family_expires_at, now)

    store_insert(engine, record)

    %TokenResult{
      token: token,
      user_id: user_id,
      family_id: family_id,
      generation: 0,
      expires_at: family_expires_at,
      idle_expires_at: record.idle_expires_at
    }
  end

  @doc """
  Exchange a refresh token for its successor ([N-26]).

  The ten checks run in the specified order, which is observable and normative
  ([N-28]): parse, pepper lookup, record lookup, verifier proof, reuse, revoked,
  absolute expiry, idle expiry, sender binding, rotate.

  Returns `{:ok, t:token_result/0}` or `{:error, %NebulaToken.Failure{}}`.
  `:CONFLICT` means a concurrent refresh won the compare-and-set: nothing was
  rotated, and the client SHOULD retry once ([N-35]).
  """
  @spec refresh(t(), term(), String.t() | nil) :: {:ok, token_result()} | {:error, Failure.t()}
  def refresh(%__MODULE__{} = engine, token, device_id \\ nil) do
    case resolve(engine, token) do
      {:ok, record, record_pepper} ->
        check_state(engine, record, record_pepper, device_id, engine.clock.())

      {:error, %Failure{}} = failure ->
        failure
    end
  end

  @doc """
  Revoke the family a token belongs to ([N-36]). Returns the number of records
  revoked.

  **Authenticated**: steps 1–4 of [N-26] run exactly as in `refresh/3`, verifier
  proof included. §3 designates the selector as a *public* lookup key — it is
  safe to index, it appears in logs, and it survives a database dump that this
  specification otherwise renders inert. If a selector alone could terminate a
  session, reading one would be an unauthenticated denial of service against an
  arbitrary user. Administrative paths that legitimately have no token use
  `revoke_family/2` and `revoke_all_for_user/2`.

  Succeeds whatever the record's status, so a client can still log out with a
  token that was already rotated or revoked. It takes no device identifier and
  performs no sender-binding check: sender binding is not required to log out.
  """
  @spec revoke_token(t(), term()) ::
          {:ok, revoke_result()} | {:error, Failure.t()}
  def revoke_token(%__MODULE__{} = engine, token) do
    case resolve(engine, token) do
      {:ok, record, _record_pepper} ->
        revoked = store_revoke_family(engine, record.family_id)
        {:ok, %{user_id: record.user_id, family_id: record.family_id, revoked: revoked}}

      {:error, %Failure{}} = failure ->
        failure
    end
  end

  @doc """
  Revoke a whole family by its server-side identifier ([N-37]). Returns the
  number of records revoked; idempotent.

  Requires no token. Intended for administrative and incident-response paths —
  the caller is responsible for authorising it.
  """
  @spec revoke_family(t(), String.t()) :: non_neg_integer()
  def revoke_family(%__MODULE__{} = engine, family_id),
    do: store_revoke_family(engine, family_id)

  @doc """
  Revoke every session of a user ([N-37]) — password change, "log out all
  devices", compromise response. Returns the number of records revoked;
  idempotent.
  """
  @spec revoke_all_for_user(t(), String.t()) :: non_neg_integer()
  def revoke_all_for_user(%__MODULE__{} = engine, user_id) do
    case engine.store_mod.revoke_user(engine.store, user_id) do
      {:ok, n} when is_integer(n) and n >= 0 -> n
      other -> store_error!(:revoke_user, other)
    end
  end

  # ── Configuration ─────────────────────────────────────────────────────────

  defp validate_peppers(peppers) when is_map(peppers) do
    # [N-24] "copy the configuration" is free on the BEAM — every term is
    # immutable, so no later act by the caller can reach inside the engine.
    # Map.new/2 still normalises the input and is where validation happens.
    Map.new(peppers, fn {kid, secret} ->
      if not NebulaToken.valid_kid?(kid) do
        raise ArgumentError,
              "[NEBULA] kid #{inspect(kid)} must be 1-#{NebulaToken.max_kid_length()} bytes from [A-Za-z0-9_-]"
      end

      # [N-11] the HMAC key is the pepper's UTF-8 encoding, so a value that has
      # no UTF-8 encoding is not a usable key. It reaches a configuration
      # trivially — a JSON secrets file carrying an unpaired surrogate, a
      # lenient UTF-16 decode — and the ten runtimes then disagree: the BEAM
      # would hand the raw bytes to :crypto.mac/4, Node substitutes U+FFFD,
      # Java substitutes '?' and Python refuses, which is three different HMAC
      # keys for one configured value. §5 resolves it by failing construction
      # everywhere. The message never quotes the secret ([N-14], [N-46]).
      if not (is_binary(secret) and String.valid?(secret)) do
        raise ArgumentError,
              "[NEBULA] pepper #{inspect(kid)} must be a string with a UTF-8 encoding " <>
                "(no unpaired surrogate)"
      end

      # [N-1] bytes of that encoding, never String.length/1. Graphemes and bytes
      # disagree by a factor of up to four: a 16-character CJK passphrase is 48
      # UTF-8 bytes and would be rejected by a grapheme count, while the same
      # module measures MAX_TOKEN_LENGTH in bytes. One unit, everywhere.
      if byte_size(secret) < NebulaToken.min_pepper_length() do
        raise ArgumentError,
              "[NEBULA] pepper #{inspect(kid)} must be a string of at least " <>
                "#{NebulaToken.min_pepper_length()} bytes"
      end

      {kid, secret}
    end)
  end

  # Never inspect the value: it is a map of secrets ([N-46]).
  defp validate_peppers(_other),
    do: raise(ArgumentError, "[NEBULA] peppers must be a map of kid => secret")

  defp integer_option!(opts, key, default, minimum) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value >= minimum ->
        value

      value ->
        raise ArgumentError,
              "[NEBULA] #{key} must be an integer >= #{minimum}, got #{inspect(value)}"
    end
  end

  defp default_clock, do: System.os_time(:second)

  # ── Steps 1-4 of [N-26], shared verbatim with revoke_token/2 ([N-36]) ──────

  defp resolve(engine, token) do
    with {:ok, parsed} <- parse(token),
         :ok <- known_kid(engine, parsed.kid),
         {:ok, record} <- lookup(engine, parsed.selector),
         {:ok, record_pepper} <- record_pepper(engine, record),
         :ok <- prove_verifier(record_pepper, parsed.verifier, record) do
      {:ok, record, record_pepper}
    end
  end

  defp parse(token) do
    case NebulaToken.parse_token(token) do
      {:ok, parsed} -> {:ok, parsed}
      :error -> {:error, %Failure{code: :MALFORMED}}
    end
  end

  defp known_kid(engine, kid) do
    if is_map_key(engine.peppers, kid), do: :ok, else: {:error, %Failure{code: :UNKNOWN_KID}}
  end

  defp lookup(engine, selector) do
    case store_find(engine, selector) do
      nil -> {:error, %Failure{code: :NOT_FOUND}}
      %Record{} = record -> {:ok, record}
    end
  end

  # [N-27] the token's kid resolved, but the record was written under a pepper
  # that has since been retired. [N-39] deliberately keeps UNKNOWN_KID free of
  # attribution even though a record was read.
  defp record_pepper(engine, record) do
    case Map.fetch(engine.peppers, record.kid) do
      {:ok, pepper} -> {:ok, pepper}
      :error -> {:error, %Failure{code: :UNKNOWN_KID}}
    end
  end

  defp prove_verifier(record_pepper, verifier, record) do
    presented = NebulaToken.hash_verifier(record_pepper, verifier)

    if NebulaToken.constant_time_equal_hex(presented, record.verifier_hash) do
      :ok
    else
      # [N-28] no family revocation here. A rotated record presented with a
      # wrong verifier must report VERIFIER_MISMATCH and leave the family alone,
      # or knowledge of a selector alone would let anyone destroy a session.
      {:error, failure(:VERIFIER_MISMATCH, record)}
    end
  end

  # ── Steps 5-10 of [N-26] ──────────────────────────────────────────────────

  defp check_state(engine, record, record_pepper, device_id, now) do
    cond do
      record.status == :rotated ->
        handle_reuse(engine, record, record_pepper, device_id, now)

      record.status == :revoked ->
        {:error, failure(:REVOKED, record)}

      now >= record.family_expires_at ->
        store_revoke_family(engine, record.family_id)
        {:error, failure(:EXPIRED_ABSOLUTE, record)}

      now >= record.idle_expires_at ->
        store_revoke_family(engine, record.family_id)
        {:error, failure(:EXPIRED_IDLE, record)}

      # [N-32] sender binding is checked against the RECORD's pepper, not the
      # active one, so a family stays verifiable across a pepper rotation.
      record.device_id_hash != nil and not device_matches?(record, record_pepper, device_id) ->
        store_revoke_family(engine, record.family_id)
        {:error, failure(:DEVICE_MISMATCH, record)}

      true ->
        rotate(engine, record, device_id, now, :active, now)
    end
  end

  # ── Reuse handling (§6.3) ─────────────────────────────────────────────────

  defp handle_reuse(engine, record, record_pepper, device_id, now) do
    if grace_window_open?(engine, record, now) do
      grace_retry(engine, record, record_pepper, device_id, now)
    else
      reuse_detected(engine, record)
    end
  end

  # [N-30] conditions 1, 2, 3, 4 and 6. Condition 5 needs a store round trip and
  # is checked in grace_retry/5.
  #
  # Condition 6 (now < family_expires_at) is what stops a grace retry from
  # minting a token past the family's absolute deadline: without it, a replay
  # arriving after the ceiling would be served a fresh, longer-lived successor.
  defp grace_window_open?(engine, record, now) do
    engine.reuse_grace > 0 and
      record.rotated_at != nil and
      now - record.rotated_at <= engine.reuse_grace and
      record.replaced_by_selector != nil and
      now < record.family_expires_at
  end

  defp grace_retry(engine, record, record_pepper, device_id, now) do
    case store_find(engine, record.replaced_by_selector) do
      # [N-30] condition 5: the successor exists and was never used. Any other
      # state — missing, rotated, revoked — is evidence of use and makes this a
      # theft signal instead of a retry.
      %Record{status: :active} = successor ->
        cond do
          # Binding is applied first, before anything is consumed or minted.
          record.device_id_hash != nil and not device_matches?(record, record_pepper, device_id) ->
            store_revoke_family(engine, record.family_id)
            {:error, failure(:DEVICE_MISMATCH, record)}

          # Compare-and-set: exactly one concurrent retry may consume the unused
          # successor. The loser mints nothing and reports a retryable conflict.
          not store_revoke_if_active(engine, successor.selector) ->
            {:error, failure(:CONFLICT, record)}

          true ->
            # from_status is :rotated, and rotated_at keeps its ORIGINAL value:
            # the window is anchored to the first rotation and cannot be walked
            # forward by repeated retries ([N-30]).
            rotate(engine, record, device_id, now, :rotated, record.rotated_at)
        end

      _ ->
        reuse_detected(engine, record)
    end
  end

  defp reuse_detected(engine, record) do
    store_revoke_family(engine, record.family_id)
    {:error, failure(:REUSE_DETECTED, record)}
  end

  # ── Rotation and minting (§6.4) ───────────────────────────────────────────

  defp rotate(engine, record, device_id, now, from_status, rotated_at) do
    {token, successor} =
      mint(
        engine,
        record.user_id,
        record.family_id,
        record.generation + 1,
        rotation_device_hash(engine, record, device_id),
        record.family_expires_at,
        now
      )

    store_insert(engine, successor)

    if store_mark_rotated(engine, record.selector, from_status, rotated_at, successor.selector) do
      {:ok,
       %TokenResult{
         token: token,
         user_id: record.user_id,
         family_id: record.family_id,
         generation: successor.generation,
         expires_at: successor.family_expires_at,
         idle_expires_at: successor.idle_expires_at
       }}
    else
      # [N-34] step 5. A concurrent refresh won the compare-and-set, so the
      # successor we just inserted is an orphan: revoke it and report a
      # retryable conflict. Returning a token here is what forks a family.
      store_revoke_if_active(engine, successor.selector)
      {:error, failure(:CONFLICT, record)}
    end
  end

  # [N-33] step 4: re-hash the presented device id with the ACTIVE pepper, so a
  # bound family migrates its binding forward across a pepper rotation. Reached
  # only after device_matches?/3 succeeded, so the value is known-good UTF-8.
  defp rotation_device_hash(engine, record, device_id) do
    if record.device_id_hash != nil and device_id != nil do
      NebulaToken.hash_device_id(active_pepper(engine), device_id)
    else
      record.device_id_hash
    end
  end

  defp mint(engine, user_id, family_id, generation, device_id_hash, family_expires_at, now) do
    # [N-43] platform CSPRNG. :crypto.strong_rand_bytes/1 raises on entropy
    # failure, which is the correct propagation: never fall back to a weaker
    # source.
    selector =
      NebulaToken.selector_bytes()
      |> :crypto.strong_rand_bytes()
      |> Base.url_encode64(padding: false)

    verifier = :crypto.strong_rand_bytes(NebulaToken.verifier_bytes())

    record = %Record{
      selector: selector,
      verifier_hash: NebulaToken.hash_verifier(active_pepper(engine), verifier),
      kid: engine.active_kid,
      family_id: family_id,
      generation: generation,
      user_id: user_id,
      device_id_hash: device_id_hash,
      created_at: now,
      family_expires_at: family_expires_at,
      # [N-33] step 3: the sliding deadline never exceeds the fixed ceiling.
      idle_expires_at: min(now + engine.idle_ttl, family_expires_at),
      status: :active,
      rotated_at: nil,
      replaced_by_selector: nil
    }

    token =
      Enum.join(
        [NebulaToken.prefix(), engine.active_kid, selector, Base.url_encode64(verifier, padding: false)],
        "."
      )

    {token, record}
  end

  # ── Device identifiers ────────────────────────────────────────────────────

  # [N-25] nil is "unbound"; "" is a binding like any other.
  defp issue_device_hash(_engine, nil), do: nil

  defp issue_device_hash(engine, device_id) when is_binary(device_id) do
    # [N-12] at issue the value comes from the application, so an identifier
    # with no UTF-8 encoding is a caller bug: surface it at the call site rather
    # than minting a binding that nothing can ever satisfy.
    if not String.valid?(device_id) do
      raise ArgumentError,
            "[NEBULA] device_id is not valid UTF-8 and has no defined hash ([N-12])"
    end

    NebulaToken.hash_device_id(active_pepper(engine), device_id)
  end

  defp issue_device_hash(_engine, _other),
    do: raise(ArgumentError, "[NEBULA] device_id must be a string or nil")

  defp device_matches?(%Record{device_id_hash: nil}, _record_pepper, _device_id), do: false
  # [N-32] a missing identifier against a bound record always fails.
  defp device_matches?(_record, _record_pepper, nil), do: false

  defp device_matches?(record, record_pepper, device_id) when is_binary(device_id) do
    # [N-12] on the attacker-reachable path an identifier with no UTF-8 encoding
    # is a binding failure, never an exception — and never a hash of some
    # replacement-character stand-in, which would disagree across languages.
    String.valid?(device_id) and
      NebulaToken.constant_time_equal_hex(
        NebulaToken.hash_device_id(record_pepper, device_id),
        record.device_id_hash
      )
  end

  defp device_matches?(_record, _record_pepper, _device_id), do: false

  # ── Store adapters: the [N-20] boundary ───────────────────────────────────

  defp store_find(engine, selector) do
    case engine.store_mod.find_by_selector(engine.store, selector) do
      {:ok, nil} -> nil
      {:ok, %Record{} = record} -> record
      other -> store_error!(:find_by_selector, other)
    end
  end

  defp store_insert(engine, record) do
    case engine.store_mod.insert(engine.store, record) do
      :ok -> :ok
      other -> store_error!(:insert, other)
    end
  end

  defp store_mark_rotated(engine, selector, from_status, rotated_at, replaced_by_selector) do
    engine.store_mod.mark_rotated(
      engine.store,
      selector,
      from_status,
      rotated_at,
      replaced_by_selector
    )
    |> case do
      {:ok, applied} when is_boolean(applied) -> applied
      other -> store_error!(:mark_rotated, other)
    end
  end

  defp store_revoke_if_active(engine, selector) do
    case engine.store_mod.revoke_if_active(engine.store, selector) do
      {:ok, applied} when is_boolean(applied) -> applied
      other -> store_error!(:revoke_if_active, other)
    end
  end

  defp store_revoke_family(engine, family_id) do
    case engine.store_mod.revoke_family(engine.store, family_id) do
      {:ok, n} when is_integer(n) and n >= 0 -> n
      other -> store_error!(:revoke_family, other)
    end
  end

  # [N-20] the store could not answer. Raising is the native error channel and
  # the only way to guarantee the operation fails closed: the caller cannot
  # receive a token for state that was not written, and cannot be told a
  # revocation happened when it did not.
  defp store_error!(operation, {:error, reason}), do: raise(StoreError, {operation, reason})

  defp store_error!(operation, other),
    do: raise(StoreError, {operation, {:unexpected_return, other}})

  # ── Misc ──────────────────────────────────────────────────────────────────

  # [N-39] attribution for security monitoring, without a second lookup of a
  # token you were told never to log.
  defp failure(code, %Record{} = record),
    do: %Failure{code: code, user_id: record.user_id, family_id: record.family_id}

  defp active_pepper(engine), do: Map.fetch!(engine.peppers, engine.active_kid)
end
