defmodule NebulaToken.BehaviorVectors.ControllableStore do
  @moduledoc """
  `NebulaToken.MemoryStore` plus the one lever the vectors need: `failNextCas`,
  which makes the next call to a named compare-and-set report "did not apply"
  exactly once ([N-17], [N-18]).

  It is deliberately not a mock — every other call goes to the real store, so a
  scenario still observes real record states.
  """
  @behaviour NebulaToken.Store

  alias NebulaToken.MemoryStore

  def start_link do
    {:ok, inner} = MemoryStore.start_link()
    {:ok, control} = Agent.start_link(fn -> %{} end)
    {:ok, %{inner: inner, control: control}}
  end

  @doc "Arm a one-shot CAS failure. `method` is the spelling used by the vectors."
  def fail_next_cas(%{control: control}, method),
    do: Agent.update(control, &Map.put(&1, method, true))

  @doc "Every record currently stored. Not part of the store contract."
  def all(%{inner: inner}), do: MemoryStore.all(inner)

  @impl true
  def find_by_selector(%{inner: inner}, selector),
    do: MemoryStore.find_by_selector(inner, selector)

  @impl true
  def insert(%{inner: inner}, record), do: MemoryStore.insert(inner, record)

  @impl true
  def mark_rotated(store, selector, from_status, rotated_at, replaced_by_selector) do
    if armed?(store, "markRotated") do
      {:ok, false}
    else
      MemoryStore.mark_rotated(store.inner, selector, from_status, rotated_at, replaced_by_selector)
    end
  end

  @impl true
  def revoke_if_active(store, selector) do
    if armed?(store, "revokeIfActive") do
      {:ok, false}
    else
      MemoryStore.revoke_if_active(store.inner, selector)
    end
  end

  @impl true
  def revoke_family(%{inner: inner}, family_id), do: MemoryStore.revoke_family(inner, family_id)

  @impl true
  def revoke_user(%{inner: inner}, user_id), do: MemoryStore.revoke_user(inner, user_id)

  defp armed?(%{control: control}, method) do
    Agent.get_and_update(control, fn state ->
      {Map.get(state, method, false), Map.delete(state, method)}
    end)
  end
end

defmodule NebulaToken.BehaviorVectors.Runner do
  @moduledoc """
  Runner for the normative behavioral suite, `spec/behavior-vectors.json`
  ([N-47] §9.2, [N-49]).

  The scenarios are data. This module is the only language-specific part, which
  is what stops the ten ports from drifting apart the way ten hand-written
  suites did. Its op vocabulary is the `runner.ops` block of the vector file.
  """

  import ExUnit.Assertions

  alias NebulaToken.BehaviorVectors.ControllableStore
  alias NebulaToken.{Engine, Failure}

  @vectors NebulaToken.SpecVectors.load("behavior-vectors.json")

  # Conditions from `runner.conditions` that this runtime satisfies.
  #
  # `runtime-admits-invalid-unicode-strings` is NOT among them. `String.t()` on
  # the BEAM is by definition a UTF-8 binary, and an unpaired surrogate has no
  # UTF-8 encoding, so an Elixir string cannot hold one — the vector file itself
  # scopes the condition to "JavaScript, Java, C#, Dart and Python", excluding
  # UTF-8-only string types.
  #
  # The underlying [N-12] requirement is not skipped: engine_test.exs proves it
  # against <<0xED, 0xA0, 0x80>>, the WTF-8 byte sequence an unpaired surrogate
  # would encode to, which String.valid?/1 rejects and which the engine must
  # treat as a binding failure rather than an exception.
  @satisfied_conditions []

  # 32 zero bytes, canonically encoded: well-formed, and never the real secret.
  @forged_verifier String.duplicate("A", 43)
  @forged_selector String.duplicate("A", 22)

  def vectors, do: @vectors
  def scenarios, do: @vectors["scenarios"]
  def satisfied_conditions, do: @satisfied_conditions

  def satisfied?(nil), do: true
  def satisfied?(condition), do: condition in @satisfied_conditions

  @doc """
  Execute every scenario in the file and report what **actually ran** ([N-48]).

  The two lists are accumulated by running the scenarios, never derived from the
  file's own counts. That is the whole point: a runner that computes
  `executed = total - skipped` reports a number it did not earn, and stays green
  after someone narrows the loop it iterates. Here, iterating a subset — or
  nothing at all — makes `executed + skipped` disagree with `counts.scenarios`
  and fails the suite, which is what the requirement asks for.
  """
  @spec run_all() :: %{executed: [String.t()], skipped: [{String.t(), String.t()}]}
  def run_all do
    outcome =
      Enum.reduce(scenarios(), %{executed: [], skipped: []}, fn scenario, acc ->
        if satisfied?(scenario["condition"]) do
          run_scenario(scenario)
          %{acc | executed: [scenario["id"] | acc.executed]}
        else
          %{acc | skipped: [{scenario["id"], scenario["condition"]} | acc.skipped]}
        end
      end)

    %{executed: Enum.reverse(outcome.executed), skipped: Enum.reverse(outcome.skipped)}
  end

  @doc "Execute one scenario by id. Fails on the first divergence."
  def run(id) do
    scenario = Enum.find(scenarios(), &(&1["id"] == id)) || flunk("unknown scenario #{id}")
    run_scenario(scenario)
  end

  defp run_scenario(scenario) do
    config = Map.merge(@vectors["defaults"], scenario["config"] || %{})
    {:ok, store} = ControllableStore.start_link()
    {:ok, clock} = Agent.start_link(fn -> config["now"] end)

    state = %{
      scenario: scenario,
      config: config,
      store: store,
      clock: clock,
      engine: build(config, store, clock, config["peppers"], config["activeKid"]),
      bindings: %{},
      # Raw verifier parts of every token handed out, and every non-empty device
      # identifier presented, for `expectNoRawSecrets`.
      secrets: [],
      device_ids: MapSet.new()
    }

    scenario["steps"]
    |> Enum.with_index()
    |> Enum.reduce(state, fn {step, index}, acc -> run_step(acc, step, index) end)

    :ok
  end

  defp build(config, store, clock, kids, active_kid) do
    Engine.new(
      peppers: Map.new(kids, fn kid -> {kid, @vectors["peppers"][kid]} end),
      active_kid: active_kid,
      store_mod: ControllableStore,
      store: store,
      absolute_ttl_seconds: config["absoluteTtlSeconds"],
      idle_ttl_seconds: config["idleTtlSeconds"],
      reuse_grace_seconds: config["reuseGraceSeconds"],
      clock: fn -> Agent.get(clock, & &1) end
    )
  end

  # ── Ops ───────────────────────────────────────────────────────────────────

  defp run_step(state, %{"op" => "issue"} = step, index) do
    expect = step["expect"] || %{}
    device_id = device_of(state, step, index)

    refute expect["ok"] == false, context(state, index, "no scenario expects issue to fail")

    result = Engine.issue(state.engine, step["userId"], device_id)
    check_success(state, result, expect, index)

    state
    |> bind(step["bind"], result)
    |> track_secret(result.token)
    |> track_device(device_id)
  end

  defp run_step(state, %{"op" => "refresh"} = step, index) do
    expect = step["expect"] || %{}
    token = resolve_token(state, step["token"], index)
    result = Engine.refresh(state.engine, token, device_of(state, step, index))

    if expects_success?(expect) do
      case result do
        {:ok, success} ->
          check_success(state, success, expect, index)
          state |> bind(step["bind"], success) |> track_secret(success.token)

        other ->
          flunk(context(state, index, "expected success, got #{inspect(other)}"))
      end
    else
      check_failure(state, result, expect, index)
      state
    end
  end

  defp run_step(state, %{"op" => "revokeToken"} = step, index) do
    expect = step["expect"] || %{}
    token = resolve_token(state, step["token"], index)
    result = Engine.revoke_token(state.engine, token)

    if expect["ok"] == false do
      # The same check as the refresh branch, attribution included: [N-39]
      # governs every failure result, and revokeToken resolves its record at
      # step 3 before proving the verifier at step 4 ([N-36]).
      check_failure(state, result, expect, index)
    else
      case result do
        {:ok, success} -> check_revoked(state, success.revoked, expect, index)
        other -> flunk(context(state, index, "expected success, got #{inspect(other)}"))
      end
    end

    state
  end

  defp run_step(state, %{"op" => "revokeFamilyOf"} = step, index) do
    binding = fetch_binding(state, step["of"], index)
    revoked = Engine.revoke_family(state.engine, binding.family_id)
    check_revoked(state, revoked, step["expect"] || %{}, index)
    state
  end

  defp run_step(state, %{"op" => "revokeUser"} = step, index) do
    revoked = Engine.revoke_all_for_user(state.engine, step["userId"])
    check_revoked(state, revoked, step["expect"] || %{}, index)
    state
  end

  defp run_step(state, %{"op" => "advance"} = step, _index) do
    Agent.update(state.clock, &(&1 + step["seconds"]))
    state
  end

  defp run_step(state, %{"op" => "reconfigure"} = step, _index) do
    # A NEW engine over the SAME store: this is a pepper rotation, not a reset.
    %{
      state
      | engine: build(state.config, state.store, state.clock, step["peppers"], step["activeKid"])
    }
  end

  defp run_step(state, %{"op" => "failNextCas"} = step, _index) do
    ControllableStore.fail_next_cas(state.store, step["method"])
    state
  end

  defp run_step(state, %{"op" => "expectStatusCounts"} = step, index) do
    actual = state.store |> ControllableStore.all() |> Enum.frequencies_by(& &1.status)

    for {status, expected} <- step["counts"] do
      got = Map.get(actual, String.to_existing_atom(status), 0)

      assert got == expected,
             context(state, index, "expected #{expected} #{status}, got #{got} (#{inspect(actual)})")
    end

    state
  end

  defp run_step(state, %{"op" => "expectNoRawSecrets"}, index) do
    dump =
      state.store
      |> ControllableStore.all()
      |> inspect(limit: :infinity, printable_limit: :infinity)

    for secret <- state.secrets do
      refute String.contains?(dump, secret),
             context(state, index, "a raw verifier reached the store ([N-14])")
    end

    for device_id <- state.device_ids do
      refute String.contains?(dump, device_id),
             context(state, index, "a raw device identifier reached the store ([N-14])")
    end

    state
  end

  defp run_step(state, step, index),
    do: flunk(context(state, index, "unknown op #{inspect(step["op"])}"))

  # ── Expectations ──────────────────────────────────────────────────────────

  # Mirrors the reference runner: a step with neither `ok` nor `error` expects
  # success.
  defp expects_success?(expect),
    do: expect["ok"] == true or (expect["ok"] == nil and expect["error"] == nil)

  defp check_success(state, result, expect, index) do
    if expect["generation"] != nil do
      assert result.generation == expect["generation"],
             context(state, index, "expected generation #{expect["generation"]}, got #{result.generation}")
    end

    if expect["kid"] != nil do
      kid = result.token |> String.split(".") |> Enum.at(1)
      assert kid == expect["kid"], context(state, index, "expected kid #{expect["kid"]}, got #{kid}")
    end

    if expect["sameFamilyAs"] != nil do
      other = fetch_binding(state, expect["sameFamilyAs"], index)

      assert result.family_id == other.family_id,
             context(state, index, "family_id changed across rotation")
    end

    if expect["sameExpiresAtAs"] != nil do
      other = fetch_binding(state, expect["sameExpiresAtAs"], index)

      assert result.expires_at == other.expires_at,
             context(state, index, "absolute deadline moved: #{other.expires_at} -> #{result.expires_at}")
    end

    if expect["idleEqualsExpires"] == true do
      assert result.idle_expires_at == result.expires_at,
             context(state, index, "idle_expires_at #{result.idle_expires_at} should be clamped to #{result.expires_at}")
    end

    :ok
  end

  defp check_failure(state, result, expect, index) do
    case result do
      {:error, %Failure{} = failure} ->
        assert Atom.to_string(failure.code) == expect["error"],
               context(state, index, "expected #{expect["error"]}, got #{failure.code}")

        check_attribution(state, failure, expect, index)

      other ->
        flunk(context(state, index, "expected #{expect["error"]}, got #{inspect(other)}"))
    end
  end

  # [N-39] attribution, tri-state. `true` demands the field, `false` demands its
  # ABSENCE — the exclusion list (:MALFORMED, :UNKNOWN_KID, :NOT_FOUND) is a
  # requirement too, and a truthy-only check could never observe it. A key the
  # scenario omits asserts nothing.
  #
  # `%NebulaToken.Failure{}` always carries both keys, so "absent" here is nil.
  # check_failure/4 is shared by the refresh and revokeToken branches, which is
  # what makes the two agree: [N-39] governs every failure result, not refresh
  # alone.
  defp check_attribution(state, %Failure{} = failure, expect, index) do
    if expect["hasUserId"] != nil do
      assert (failure.user_id != nil) == expect["hasUserId"],
             context(state, index, "expected user_id #{presence(expect["hasUserId"])} ([N-39])")
    end

    if expect["hasFamilyId"] != nil do
      assert (failure.family_id != nil) == expect["hasFamilyId"],
             context(state, index, "expected family_id #{presence(expect["hasFamilyId"])} ([N-39])")
    end
  end

  defp presence(true), do: "present"
  defp presence(false), do: "absent"

  defp check_revoked(state, actual, expect, index) do
    if expect["revoked"] != nil do
      assert actual == expect["revoked"],
             context(state, index, "expected #{expect["revoked"]} revoked, got #{actual}")
    end
  end

  # ── Helpers ───────────────────────────────────────────────────────────────

  defp resolve_token(_state, %{"literal" => literal}, _index), do: literal

  defp resolve_token(state, %{"ref" => ref} = token, index) do
    bound = fetch_binding(state, ref, index)

    case token["forge"] do
      nil -> bound.token
      "verifier" -> replace_part(bound.token, 3, @forged_verifier)
      "unknownKid" -> replace_part(bound.token, 1, "zz")
      "unknownSelector" -> replace_part(bound.token, 2, @forged_selector)
      other -> flunk(context(state, index, "unknown forge #{inspect(other)}"))
    end
  end

  defp resolve_token(state, other, index),
    do: flunk(context(state, index, "step has no usable token reference: #{inspect(other)}"))

  defp replace_part(token, position, replacement) do
    token |> String.split(".") |> List.replace_at(position, replacement) |> Enum.join(".")
  end

  defp device_of(state, step, index) do
    case step["deviceIdKind"] do
      nil ->
        step["deviceId"]

      kind ->
        flunk(context(state, index, "deviceIdKind #{inspect(kind)} is not supported by this runtime"))
    end
  end

  defp fetch_binding(state, name, index) do
    Map.get(state.bindings, name) ||
      flunk(context(state, index, "unknown binding #{inspect(name)}"))
  end

  defp bind(state, nil, _result), do: state

  defp bind(state, name, result) do
    binding = %{
      token: result.token,
      family_id: result.family_id,
      expires_at: result.expires_at
    }

    %{state | bindings: Map.put(state.bindings, name, binding)}
  end

  defp track_secret(state, token) do
    %{state | secrets: [token |> String.split(".") |> Enum.at(3) | state.secrets]}
  end

  defp track_device(state, device_id) when device_id in [nil, ""], do: state
  defp track_device(state, device_id), do: %{state | device_ids: MapSet.put(state.device_ids, device_id)}

  defp context(state, index, message) do
    requirements = Enum.join(state.scenario["requirements"] || [], ", ")
    "[#{state.scenario["id"]}] step #{index} (#{requirements}): #{message}"
  end
end

defmodule NebulaToken.BehaviorVectorsTest do
  @moduledoc """
  Executes every scenario in `spec/behavior-vectors.json` ([N-47], [N-49]).

  One ExUnit test per scenario, generated from the file at compile time, so a
  divergence names the scenario that diverged. Conditional scenarios this
  runtime does not satisfy are tagged `:skip` and reported by id.
  """
  use ExUnit.Case, async: true

  alias NebulaToken.BehaviorVectors.Runner

  @vectors Runner.vectors()

  test "the published counts describe the file that was executed ([N-48])" do
    scenarios = @vectors["scenarios"]

    assert @vectors["spec_version"] == NebulaToken.spec_version()
    assert scenarios != []
    assert length(scenarios) == @vectors["counts"]["scenarios"]

    assert Enum.count(scenarios, &is_nil(&1["condition"])) == @vectors["counts"]["unconditional"]
  end

  test "every applicable scenario is really executed, and skips are reported by id ([N-48])" do
    # `outcome` is accumulated while the scenarios run, so the numbers asserted
    # below are the numbers earned. Deriving them from the file instead would
    # let a runner that iterates a subset — or zero cases — still report the
    # published count, which [N-48] calls a conformance failure, not a pass.
    outcome = Runner.run_all()
    executed = length(outcome.executed)
    total = length(@vectors["scenarios"])

    assert executed + length(outcome.skipped) == @vectors["counts"]["scenarios"],
           "every published scenario must be either executed or explicitly skipped"

    assert executed >= @vectors["counts"]["unconditional"],
           "every unconditional scenario must be executed"

    assert outcome.executed == Enum.uniq(outcome.executed), "a scenario ran twice"

    # A runner MUST execute every unconditional scenario; only a scenario
    # carrying a `condition` this runtime does not satisfy may be skipped.
    assert Enum.all?(outcome.skipped, fn {_id, condition} -> condition != nil end)

    report =
      Enum.map(outcome.skipped, fn {id, condition} ->
        "\n  skipped #{id} (condition: #{condition})"
      end)

    IO.puts([
      "\n[behavior-vectors] executed #{executed}/#{total} scenarios",
      report,
      if(outcome.skipped == [], do: "\n  (none skipped)", else: ""),
      "\n"
    ])
  end

  for scenario <- @vectors["scenarios"] do
    id = scenario["id"]
    name = "#{id}: #{scenario["title"]}"

    if Runner.satisfied?(scenario["condition"]) do
      test name do
        Runner.run(unquote(id))
      end
    else
      @tag skip: "runtime does not satisfy condition: #{scenario["condition"]}"
      test name do
        Runner.run(unquote(id))
      end
    end
  end
end
