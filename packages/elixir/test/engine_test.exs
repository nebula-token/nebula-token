defmodule NebulaToken.EngineTest.ExplodingStore do
  @moduledoc """
  A store whose chosen callback reports an infrastructure failure ([N-20]).

  Everything else delegates to `NebulaToken.MemoryStore`, so the scenario under
  test is "one call to the database failed", not "the store is a stub".
  """
  @behaviour NebulaToken.Store

  alias NebulaToken.MemoryStore

  def start_link(fail_on) do
    {:ok, inner} = MemoryStore.start_link()
    {:ok, %{inner: inner, fail_on: fail_on}}
  end

  @impl true
  def find_by_selector(store, selector),
    do: guard(store, :find_by_selector, fn -> MemoryStore.find_by_selector(store.inner, selector) end)

  @impl true
  def insert(store, record),
    do: guard(store, :insert, fn -> MemoryStore.insert(store.inner, record) end)

  @impl true
  def mark_rotated(store, selector, from_status, rotated_at, replaced_by) do
    guard(store, :mark_rotated, fn ->
      MemoryStore.mark_rotated(store.inner, selector, from_status, rotated_at, replaced_by)
    end)
  end

  @impl true
  def revoke_if_active(store, selector),
    do: guard(store, :revoke_if_active, fn -> MemoryStore.revoke_if_active(store.inner, selector) end)

  @impl true
  def revoke_family(store, family_id),
    do: guard(store, :revoke_family, fn -> MemoryStore.revoke_family(store.inner, family_id) end)

  @impl true
  def revoke_user(store, user_id),
    do: guard(store, :revoke_user, fn -> MemoryStore.revoke_user(store.inner, user_id) end)

  defp guard(%{fail_on: fail_on}, callback, run) do
    if callback == fail_on, do: {:error, :database_is_on_fire}, else: run.()
  end
end

defmodule NebulaToken.EngineTest.RogueStore do
  @moduledoc """
  A store that answers outside its contract — the shape a hand-rolled adapter
  produces when someone forgets to wrap a boolean ([N-20]).
  """
  @behaviour NebulaToken.Store

  alias NebulaToken.MemoryStore

  def start_link do
    {:ok, inner} = MemoryStore.start_link()
    {:ok, %{inner: inner}}
  end

  @impl true
  def find_by_selector(s, selector), do: MemoryStore.find_by_selector(s.inner, selector)
  @impl true
  def insert(s, record), do: MemoryStore.insert(s.inner, record)
  @impl true
  def mark_rotated(_s, _selector, _from_status, _rotated_at, _replaced_by), do: :ok
  @impl true
  def revoke_if_active(s, selector), do: MemoryStore.revoke_if_active(s.inner, selector)
  @impl true
  def revoke_family(s, family_id), do: MemoryStore.revoke_family(s.inner, family_id)
  @impl true
  def revoke_user(s, user_id), do: MemoryStore.revoke_user(s.inner, user_id)
end

defmodule NebulaToken.EngineTest.BarrierStore do
  @moduledoc """
  `NebulaToken.MemoryStore` with a rendezvous on `find_by_selector/2`.

  Real concurrency is not a proof of anything unless the contention is real: if
  the scheduler happens to run the refreshes one after another, the second one
  reads a `:rotated` record and takes the reuse path, and the compare-and-set in
  [N-34] step 3 is never exercised. Holding every caller until all of them have
  read the record forces the exact interleaving the requirement exists for —
  N refreshes that all observed `:active`.
  """
  @behaviour NebulaToken.Store

  alias NebulaToken.MemoryStore

  @timeout_ms 5_000

  def start_link(parties) do
    {:ok, inner} = MemoryStore.start_link()
    {:ok, gate} = Agent.start_link(fn -> 0 end)
    {:ok, %{inner: inner, gate: gate, parties: parties}}
  end

  def all(%{inner: inner}), do: MemoryStore.all(inner)

  @impl true
  def find_by_selector(store, selector) do
    # Read first, then join the barrier: releasing a caller only once every
    # caller has already read guarantees that all N observed the same `:active`
    # record. Waiting before the read would leave a window in which a released
    # caller finishes its rotation before a slower one gets to read.
    result = MemoryStore.find_by_selector(store.inner, selector)
    Agent.update(store.gate, &(&1 + 1))
    await(store, System.monotonic_time(:millisecond) + @timeout_ms)
    result
  end

  @impl true
  def insert(s, record), do: MemoryStore.insert(s.inner, record)
  @impl true
  def mark_rotated(s, selector, from_status, rotated_at, replaced_by),
    do: MemoryStore.mark_rotated(s.inner, selector, from_status, rotated_at, replaced_by)

  @impl true
  def revoke_if_active(s, selector), do: MemoryStore.revoke_if_active(s.inner, selector)
  @impl true
  def revoke_family(s, family_id), do: MemoryStore.revoke_family(s.inner, family_id)
  @impl true
  def revoke_user(s, user_id), do: MemoryStore.revoke_user(s.inner, user_id)

  # Bounded, so a wrong `parties` count fails the assertion rather than hanging
  # the suite.
  defp await(store, deadline) do
    cond do
      Agent.get(store.gate, & &1) >= store.parties ->
        :ok

      System.monotonic_time(:millisecond) > deadline ->
        :ok

      true ->
        Process.sleep(1)
        await(store, deadline)
    end
  end
end

defmodule NebulaToken.EngineTest do
  @moduledoc """
  Language-specific tests: the properties that cannot be expressed as portable
  behavior vectors. Everything cross-language lives in
  `spec/behavior-vectors.json` and runs from `behavior_test.exs`.
  """
  use ExUnit.Case, async: true

  alias NebulaToken.EngineTest.{BarrierStore, ExplodingStore, RogueStore}
  alias NebulaToken.{Engine, Failure, MemoryStore, Record, StoreError}

  @pepper "pepper-one-0123456789abcdef0123456789ab"
  @hash String.duplicate("a", 64)

  # WTF-8 encoding of U+D800. `String.valid?/1` rejects it: it is exactly the
  # value an unpaired surrogate would become if a JSON or UTF-16 boundary let one
  # through, and the only way this runtime can hold "a string that is not valid
  # Unicode" ([N-12]).
  @invalid_unicode <<0xED, 0xA0, 0x80>>

  defp make_engine(opts \\ []) do
    {:ok, store} = MemoryStore.start_link()
    {:ok, clock} = Agent.start_link(fn -> 1_700_000_000 end)

    engine =
      Engine.new(
        Keyword.merge(
          [
            peppers: %{"k1" => @pepper},
            active_kid: "k1",
            store: store,
            clock: fn -> Agent.get(clock, & &1) end
          ],
          opts
        )
      )

    {engine, store, clock}
  end

  defp advance(clock, seconds), do: Agent.update(clock, &(&1 + seconds))

  defp replace_part(token, position, replacement),
    do: token |> String.split(".") |> List.replace_at(position, replacement) |> Enum.join(".")

  # ── Constant-time comparison ([N-31]) ─────────────────────────────────────

  describe "constant_time_equal_hex/2" do
    test "only two 64-character lowercase hex strings can ever compare equal" do
      assert NebulaToken.constant_time_equal_hex(@hash, @hash)
      refute NebulaToken.constant_time_equal_hex(@hash, String.duplicate("b", 64))

      # A lenient hex decode stops at the first invalid character and compares
      # the decoded prefixes, so every case below would otherwise compare EQUAL
      # — and a corrupted stored hash would keep verifying instead of failing
      # closed.
      refute NebulaToken.constant_time_equal_hex("abc", "abd")
      refute NebulaToken.constant_time_equal_hex(@hash, @hash <> "   "), "space-padded CHAR column"
      refute NebulaToken.constant_time_equal_hex(@hash <> "  ", @hash <> "  ")
      refute NebulaToken.constant_time_equal_hex(@hash, @hash <> "\n"), "trailing newline"
      refute NebulaToken.constant_time_equal_hex(@hash, @hash <> "zzzz"), "junk suffix"
      refute NebulaToken.constant_time_equal_hex(@hash, String.upcase(@hash)), "case is not folded"

      # Both sides upper-cased: a `case: :mixed` decode would call these equal.
      refute NebulaToken.constant_time_equal_hex(String.upcase(@hash), String.upcase(@hash)),
             "uppercase never verifies, even against itself"

      refute NebulaToken.constant_time_equal_hex(
               binary_part(@hash, 0, 63),
               binary_part(@hash, 0, 63)
             ),
             "truncated column"

      refute NebulaToken.constant_time_equal_hex("", ""), "empty is never equal"
    end

    test "never raises, whatever it is handed" do
      hostile = [
        nil,
        42,
        :atom,
        [],
        {},
        %{},
        "",
        "zz",
        String.duplicate(" ", 64),
        <<0xFF, 0xFE>>,
        @invalid_unicode
      ]

      for value <- hostile do
        refute NebulaToken.constant_time_equal_hex(value, @hash), inspect(value)
        refute NebulaToken.constant_time_equal_hex(@hash, value), inspect(value)
        refute NebulaToken.constant_time_equal_hex(value, value), inspect(value)
      end
    end

    test "a stored hash corrupted after the fact fails closed instead of verifying" do
      {engine, store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")
      [row] = MemoryStore.all(store)

      # Same record, but an ETL job upper-cased the hex column.
      corrupted = %{
        row
        | selector: String.duplicate("x", 22),
          verifier_hash: String.upcase(row.verifier_hash)
      }

      :ok = MemoryStore.insert(store, corrupted)

      forged = replace_part(issued.token, 2, String.duplicate("x", 22))
      assert {:error, %Failure{code: :VERIFIER_MISMATCH}} = Engine.refresh(engine, forged)
    end
  end

  # ── Concurrency ([N-17], [N-34], [N-35]) ──────────────────────────────────

  describe "concurrent refreshes of one token" do
    test "exactly one wins; the loser gets CONFLICT and the family does not fork" do
      {engine, store} = barrier_engine(2)
      issued = Engine.issue(engine, "u1")

      results = concurrent_refreshes(engine, issued.token, 2)

      assert Enum.count(results, &match?({:ok, _}, &1)) == 1, "exactly one refresh may win"

      assert Enum.count(results, &match?({:error, %Failure{code: :CONFLICT}}, &1)) == 1,
             "the loser must report CONFLICT: #{inspect(results)}"

      assert active_count(store) == 1, "the family must not fork into two live lineages"
    end

    test "a burst of sixteen still leaves exactly one active record" do
      {engine, store} = barrier_engine(16)
      issued = Engine.issue(engine, "u1")

      results = concurrent_refreshes(engine, issued.token, 16)

      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      assert Enum.count(results, &match?({:error, %Failure{code: :CONFLICT}}, &1)) == 15
      assert active_count(store) == 1

      # [N-35]: CONFLICT revokes nothing beyond the orphan successors the engine
      # itself inserted, so the predecessor is merely rotated — not burned.
      assert Enum.count(MemoryStore.all(store.inner), &(&1.status == :rotated)) == 1
    end
  end

  defp barrier_engine(parties) do
    {:ok, store} = BarrierStore.start_link(parties)

    engine =
      Engine.new(
        peppers: %{"k1" => @pepper},
        active_kid: "k1",
        store_mod: BarrierStore,
        store: store
      )

    {engine, store}
  end

  defp concurrent_refreshes(engine, token, count) do
    1..count
    |> Enum.map(fn _ -> Task.async(fn -> Engine.refresh(engine, token) end) end)
    |> Task.await_many(30_000)
  end

  defp active_count(store), do: Enum.count(BarrierStore.all(store), &(&1.status == :active))

  # ── Store failures fail closed ([N-20]) ───────────────────────────────────

  describe "infrastructure failures" do
    test "a failing insert must not hand back a token for state that was never written" do
      engine = exploding_engine(:insert)
      assert_raise StoreError, fn -> Engine.issue(engine, "u1") end
    end

    test "a failing lookup is raised, never converted into NOT_FOUND" do
      engine = exploding_engine(:find_by_selector)
      issued = Engine.issue(engine, "u1")
      assert_raise StoreError, fn -> Engine.refresh(engine, issued.token) end
      assert_raise StoreError, fn -> Engine.revoke_token(engine, issued.token) end
    end

    test "a failing revoke_family must not be reported as a successful revocation" do
      engine = exploding_engine(:revoke_family)
      issued = Engine.issue(engine, "u1")
      assert {:ok, _} = Engine.refresh(engine, issued.token)

      # The replay must attempt a family revocation; the failure propagates
      # rather than being swallowed into a confident REUSE_DETECTED.
      assert_raise StoreError, fn -> Engine.refresh(engine, issued.token) end
      assert_raise StoreError, fn -> Engine.revoke_family(engine, issued.family_id) end
    end

    test "a failing revoke_user must not report a count it never achieved" do
      engine = exploding_engine(:revoke_user)
      Engine.issue(engine, "u1")
      assert_raise StoreError, fn -> Engine.revoke_all_for_user(engine, "u1") end
    end

    test "a failing compare-and-set is an infrastructure failure, not a CONFLICT" do
      engine = exploding_engine(:mark_rotated)
      issued = Engine.issue(engine, "u1")
      assert_raise StoreError, fn -> Engine.refresh(engine, issued.token) end
    end

    test "a store that answers outside its contract fails closed too" do
      {:ok, store} = RogueStore.start_link()

      engine =
        Engine.new(
          peppers: %{"k1" => @pepper},
          active_kid: "k1",
          store_mod: RogueStore,
          store: store
        )

      issued = Engine.issue(engine, "u1")

      error = assert_raise StoreError, fn -> Engine.refresh(engine, issued.token) end
      assert error.operation == :mark_rotated
      assert Exception.message(error) =~ "mark_rotated"
    end

    test "the exception carries the operation and the store's reason" do
      engine = exploding_engine(:insert)
      error = assert_raise StoreError, fn -> Engine.issue(engine, "u1") end
      assert error.operation == :insert
      assert error.reason == :database_is_on_fire
    end
  end

  defp exploding_engine(fail_on) do
    {:ok, store} = ExplodingStore.start_link(fail_on)

    Engine.new(
      peppers: %{"k1" => @pepper},
      active_kid: "k1",
      store_mod: ExplodingStore,
      store: store
    )
  end

  # ── Configuration (§5, [N-1], [N-23], [N-24]) ─────────────────────────────

  describe "Engine.new/1 validation" do
    test "rejects every violation of §5" do
      {:ok, store} = MemoryStore.start_link()

      bad = fn opts ->
        assert_raise ArgumentError, fn ->
          Engine.new(Keyword.merge([store: store], opts))
        end
      end

      bad.(peppers: %{"k1" => "short"}, active_kid: "k1")
      bad.(peppers: %{"k1" => @pepper}, active_kid: "nope")
      bad.(peppers: %{"k.1" => @pepper}, active_kid: "k.1")
      bad.(peppers: %{"k+1" => @pepper}, active_kid: "k+1")
      bad.(peppers: %{"" => @pepper}, active_kid: "")
      bad.(peppers: %{String.duplicate("k", 65) => @pepper}, active_kid: String.duplicate("k", 65))
      bad.(peppers: [{"k1", @pepper}], active_kid: "k1")
      bad.(peppers: %{"k1" => @pepper}, active_kid: "k1", absolute_ttl_seconds: 0)
      bad.(peppers: %{"k1" => @pepper}, active_kid: "k1", idle_ttl_seconds: -5)
      bad.(peppers: %{"k1" => @pepper}, active_kid: "k1", reuse_grace_seconds: -1)
      bad.(peppers: %{"k1" => @pepper}, active_kid: "k1", idle_ttl_seconds: 1.5)

      # [N-11] a pepper with no UTF-8 encoding is not a usable HMAC key, and is
      # rejected for that reason and not for its length: this one is long
      # enough. The runtimes substitute different replacement characters, so
      # accepting it would give one configured value three different HMAC keys.
      bad.(peppers: %{"k1" => @invalid_unicode <> @pepper}, active_kid: "k1")
    end

    test "accepts a kid at exactly MAX_KID_LENGTH bytes" do
      {:ok, store} = MemoryStore.start_link()
      kid = String.duplicate("k", NebulaToken.max_kid_length())
      assert %Engine{} = Engine.new(peppers: %{kid => @pepper}, active_kid: kid, store: store)
    end

    test "MIN_PEPPER_LENGTH counts bytes, not characters or graphemes ([N-1])" do
      {:ok, store} = MemoryStore.start_link()

      wide = String.duplicate("日", 16)

      # The two units disagree, which is the whole point: a grapheme count would
      # reject this perfectly good 48-byte secret, while the same module measures
      # MAX_TOKEN_LENGTH in bytes.
      assert String.length(wide) == 16
      assert byte_size(wide) == 48
      assert String.length(wide) < NebulaToken.min_pepper_length()
      assert byte_size(wide) >= NebulaToken.min_pepper_length()

      assert %Engine{} = Engine.new(peppers: %{"k1" => wide}, active_kid: "k1", store: store)

      # 31 bytes is 31 characters, and is one byte short either way.
      assert_raise ArgumentError, fn ->
        Engine.new(peppers: %{"k1" => String.duplicate("a", 31)}, active_kid: "k1", store: store)
      end

      assert %Engine{} =
               Engine.new(
                 peppers: %{"k1" => String.duplicate("a", 32)},
                 active_kid: "k1",
                 store: store
               )
    end

    test "the configuration is copied: the caller cannot weaken the engine afterwards ([N-24])" do
      {:ok, store} = MemoryStore.start_link()
      peppers = %{"k1" => @pepper}
      engine = Engine.new(peppers: peppers, active_kid: "k1", store: store)

      # On the BEAM there is no in-place mutation to defend against: every term
      # is immutable, so the "copy at construction" requirement is satisfied by
      # the runtime. Rebinding the caller's map to a one-byte secret must not be
      # observable through the engine.
      _weakened = Map.put(peppers, "k1", "x")

      issued = Engine.issue(engine, "u1")
      {:ok, parsed} = NebulaToken.parse_token(issued.token)
      [row] = MemoryStore.all(store)

      assert row.verifier_hash == NebulaToken.hash_verifier(@pepper, parsed.verifier)
      assert {:ok, _} = Engine.refresh(engine, issued.token)
    end

    test "store_mod defaults to the in-memory store and is honoured when given" do
      {engine, store, _clock} = make_engine()
      assert engine.store_mod == NebulaToken.MemoryStore

      issued = Engine.issue(engine, "u1")
      assert [%Record{}] = MemoryStore.all(store)
      assert {:ok, _} = Engine.refresh(engine, issued.token)
    end
  end

  # ── Device identifiers ([N-11], [N-12]) ───────────────────────────────────

  describe "device identifiers" do
    test "issue rejects an identifier with no UTF-8 encoding, at the call site ([N-12])" do
      {engine, store, _clock} = make_engine()

      assert_raise ArgumentError, fn -> Engine.issue(engine, "u1", @invalid_unicode) end
      assert_raise ArgumentError, fn -> Engine.issue(engine, "u1", :not_a_string) end

      # Nothing was minted for a binding nothing could satisfy.
      assert MemoryStore.all(store) == []
    end

    test "a presented identifier with no UTF-8 encoding is a binding failure, never an exception ([N-12])" do
      {engine, store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1", "devA")

      assert {:error, %Failure{code: :DEVICE_MISMATCH}} =
               Engine.refresh(engine, issued.token, @invalid_unicode)

      assert Enum.all?(MemoryStore.all(store), &(&1.status == :revoked))
    end

    test "an unbound family ignores an identifier with no UTF-8 encoding ([N-12])" do
      {engine, _store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")
      assert {:ok, _} = Engine.refresh(engine, issued.token, @invalid_unicode)
    end

    test "hash_device_id applies no normalisation, trimming or case folding ([N-11])" do
      nfc = "Café"
      nfd = "Café"
      # Canonically equivalent, different bytes: the hash follows the bytes.
      assert String.equivalent?(nfc, nfd)
      refute nfc == nfd

      refute NebulaToken.hash_device_id(@pepper, nfc) == NebulaToken.hash_device_id(@pepper, nfd),
             "NFC and NFD must not be conflated"

      refute NebulaToken.hash_device_id(@pepper, "x") == NebulaToken.hash_device_id(@pepper, " x")
      refute NebulaToken.hash_device_id(@pepper, "x") == NebulaToken.hash_device_id(@pepper, "X")
    end
  end

  # ── Secrets never leave the engine ([N-14], [N-46]) ───────────────────────

  describe "secret hygiene" do
    test "no raw secret appears in anything the engine stores" do
      {engine, store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1", "devA")
      assert {:ok, _} = Engine.refresh(engine, issued.token, "devA")

      dump = store |> MemoryStore.all() |> inspect(limit: :infinity, printable_limit: :infinity)
      [_, _, _, verifier_b64] = String.split(issued.token, ".")

      refute String.contains?(dump, verifier_b64), "raw verifier"
      refute String.contains?(dump, "devA"), "raw device identifier"
      refute String.contains?(dump, @pepper), "pepper"

      for record <- MemoryStore.all(store) do
        assert record.verifier_hash =~ ~r/\A[0-9a-f]{64}\z/
        assert record.device_id_hash =~ ~r/\A[0-9a-f]{64}\z/
      end
    end

    test "inspecting the engine does not leak the peppers ([N-46])" do
      {engine, _store, _clock} = make_engine()
      refute String.contains?(inspect(engine), @pepper)
    end

    test "inspecting a parsed token does not leak the raw verifier ([N-14], [N-46])" do
      {engine, _store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")
      {:ok, parsed} = NebulaToken.parse_token(issued.token)

      rendered = inspect(parsed, limit: :infinity, printable_limit: :infinity)
      verifier = inspect(parsed.verifier, limit: :infinity, printable_limit: :infinity)

      refute String.contains?(rendered, verifier), "the raw verifier reached a debug rendering"

      # Redacted, not withheld: the field itself is unchanged, and the selector
      # is a public correlation id that stays visible.
      assert byte_size(parsed.verifier) == NebulaToken.verifier_bytes()
      assert String.contains?(rendered, parsed.selector)
    end

    test "inspecting an issue or refresh result does not leak the token ([N-14], [N-46])" do
      {engine, _store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")
      assert {:ok, refreshed} = Engine.refresh(engine, issued.token)

      opts = [limit: :infinity, printable_limit: :infinity]
      refute String.contains?(inspect(issued, opts), issued.token)
      refute String.contains?(inspect(refreshed, opts), refreshed.token)

      # The value is unchanged: the handler that hands the token to the client
      # still works.
      assert {:ok, _} = NebulaToken.parse_token(refreshed.token)
    end
  end

  # ── Result shape ([N-2], [N-38], [N-39]) ──────────────────────────────────

  describe "result shape" do
    test "timestamps are integer unix seconds ([N-2])" do
      {engine, _store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")

      assert is_integer(issued.expires_at) and is_integer(issued.idle_expires_at)
      assert issued.user_id == "u1" and issued.generation == 0

      assert {:ok, refreshed} = Engine.refresh(engine, issued.token)
      assert is_integer(refreshed.expires_at) and is_integer(refreshed.idle_expires_at)
      assert refreshed.generation == 1
    end

    test "failures carry user_id and family_id once a record is resolved ([N-39])" do
      {engine, _store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")
      assert {:ok, _} = Engine.refresh(engine, issued.token)

      assert {:error, %Failure{code: :REUSE_DETECTED, user_id: "u1", family_id: family_id}} =
               Engine.refresh(engine, issued.token)

      assert family_id == issued.family_id

      # Before a record is resolved there is nothing to attribute.
      assert {:error, %Failure{code: :MALFORMED, user_id: nil, family_id: nil}} =
               Engine.refresh(engine, "garbage")
    end

    test "the error vocabulary is exactly the ten codes of [N-38], CONFLICT included" do
      assert Enum.sort(NebulaToken.error_codes()) ==
               Enum.sort([
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
               ])
    end

    test "issued tokens are unique and parse back ([N-43])" do
      {engine, _store, _clock} = make_engine()

      seen =
        Enum.reduce(1..200, MapSet.new(), fn _, seen ->
          issued = Engine.issue(engine, "u1")
          refute MapSet.member?(seen, issued.token)
          assert {:ok, _} = NebulaToken.parse_token(issued.token)
          MapSet.put(seen, issued.token)
        end)

      assert MapSet.size(seen) == 200
    end
  end

  # ── In-memory store hygiene ([N-15], [N-21]) ──────────────────────────────

  describe "MemoryStore" do
    test "refuses a duplicate selector rather than overwriting a live record" do
      {:ok, store} = MemoryStore.start_link()

      row = %Record{
        selector: String.duplicate("A", 22),
        verifier_hash: @hash,
        kid: "k1",
        family_id: "f",
        generation: 0,
        user_id: "u1",
        device_id_hash: nil,
        created_at: 0,
        family_expires_at: 1,
        idle_expires_at: 1,
        status: :active,
        rotated_at: nil,
        replaced_by_selector: nil
      }

      assert :ok = MemoryStore.insert(store, row)
      assert {:error, {:duplicate_selector, _}} = MemoryStore.insert(store, row)
    end

    test "the compare-and-set callbacks apply only against the expected status" do
      {engine, store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")
      [row] = MemoryStore.all(store)

      assert {:ok, false} = MemoryStore.mark_rotated(store, row.selector, :rotated, 1, "x")
      assert {:ok, false} = MemoryStore.mark_rotated(store, "nope", :active, 1, "x")
      assert {:ok, true} = MemoryStore.mark_rotated(store, row.selector, :active, 1, "x")
      assert {:ok, false} = MemoryStore.revoke_if_active(store, row.selector)

      # The record is rotated now, so the token replays as reuse, not as success.
      assert {:error, %Failure{code: :REUSE_DETECTED}} = Engine.refresh(engine, issued.token)
    end

    test "revocation counts only the rows it changed, and is idempotent ([N-19])" do
      {engine, store, _clock} = make_engine()
      issued = Engine.issue(engine, "u1")

      assert {:ok, 1} = MemoryStore.revoke_family(store, issued.family_id)
      assert {:ok, 0} = MemoryStore.revoke_family(store, issued.family_id)
      assert {:ok, 0} = MemoryStore.revoke_user(store, "u1")
      assert Engine.revoke_all_for_user(engine, "u2") == 0
    end

    test "delete_expired only removes records past the family deadline ([N-15])" do
      {engine, store, clock} =
        make_engine(absolute_ttl_seconds: 100, idle_ttl_seconds: 100)

      issued = Engine.issue(engine, "u1")
      advance(clock, 10)
      assert {:ok, _} = Engine.refresh(engine, issued.token)

      assert MemoryStore.delete_expired(store, 1_700_000_099) == 0,
             "a rotated record must survive until its family deadline"

      assert length(MemoryStore.all(store)) == 2
      assert MemoryStore.delete_expired(store, 1_700_000_100) == 2
    end
  end
end
