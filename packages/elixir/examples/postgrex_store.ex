defmodule NebulaToken.Examples.PostgrexStore do
  @moduledoc """
  Production-style SQL store for NEBULA — Postgrex template.

  Wire it up with **both** options: `store_mod: NebulaToken.Examples.PostgrexStore`
  and `store: <your Postgrex pool or connection>`. Passing only `:store` leaves
  the engine talking to `NebulaToken.MemoryStore`.

  Best practices demonstrated:

    * parameterised queries only;
    * lookups keyed on the non-secret selector ([N-45]);
    * `mark_rotated/5` and `revoke_if_active/2` as real compare-and-sets — the
      `AND status = $n` clause is not decoration, it is what stops two
      concurrent refreshes from forking a family ([N-17], [N-18]);
    * `revoke_family/2` and `revoke_user/2` returning the number of rows they
      actually changed, so a repeat call answers 0 ([N-19]);
    * infrastructure failures surfaced as `{:error, reason}` rather than
      swallowed into `{:ok, false}` or `{:ok, 0}` ([N-20]);
    * rotated and revoked rows kept until the family's absolute deadline — they
      are what reuse detection reads ([N-15]) — with `delete_expired/2` for GC.

  Wrap each refresh request in `Postgrex.transaction/2` (or
  `Ecto.Repo.transaction/1`) so the successor `insert` and the predecessor
  `mark_rotated` commit atomically ([N-22]).

  Schema: `docs/STORE.md`. This file lives in `examples/` and is not compiled
  into the published package. Add `{:postgrex, "~> 0.17"}` to use it.
  """

  @behaviour NebulaToken.Store

  alias NebulaToken.Record

  @cols "selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash, " <>
          "created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector"

  @impl true
  def find_by_selector(conn, selector) do
    case query(conn, "SELECT #{@cols} FROM refresh_tokens WHERE selector = $1", [selector]) do
      {:ok, %{rows: []}} -> {:ok, nil}
      {:ok, %{rows: [row]}} -> {:ok, to_record(row)}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def insert(conn, %Record{} = r) do
    sql =
      "INSERT INTO refresh_tokens (#{@cols}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"

    params = [
      r.selector,
      r.verifier_hash,
      r.kid,
      r.family_id,
      r.generation,
      r.user_id,
      r.device_id_hash,
      r.created_at,
      r.family_expires_at,
      r.idle_expires_at,
      Atom.to_string(r.status),
      r.rotated_at,
      r.replaced_by_selector
    ]

    # A unique-violation on `selector` arrives here as {:error, %Postgrex.Error{}}
    # and MUST stay an error: overwriting a live row would destroy a session.
    case query(conn, sql, params) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def mark_rotated(conn, selector, from_status, rotated_at, replaced_by_selector) do
    sql = """
    UPDATE refresh_tokens
       SET status = 'rotated', rotated_at = $3, replaced_by_selector = $4
     WHERE selector = $1 AND status = $2
    """

    # `AND status = $2` is the compare; `num_rows` is the answer ([N-17]).
    case query(conn, sql, [
           selector,
           Atom.to_string(from_status),
           rotated_at,
           replaced_by_selector
         ]) do
      {:ok, %{num_rows: n}} -> {:ok, n == 1}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def revoke_if_active(conn, selector) do
    sql =
      "UPDATE refresh_tokens SET status = 'revoked' WHERE selector = $1 AND status = 'active'"

    case query(conn, sql, [selector]) do
      {:ok, %{num_rows: n}} -> {:ok, n == 1}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def revoke_family(conn, family_id), do: revoke_by(conn, "family_id", family_id)

  @impl true
  def revoke_user(conn, user_id), do: revoke_by(conn, "user_id", user_id)

  @doc "Operational helper: GC families past their absolute deadline ([N-15])."
  def delete_expired(conn, now) do
    case query(conn, "DELETE FROM refresh_tokens WHERE family_expires_at <= $1", [now]) do
      {:ok, %{num_rows: n}} -> {:ok, n}
      {:error, reason} -> {:error, reason}
    end
  end

  # `AND status <> 'revoked'` keeps the count to rows actually changed, which is
  # what makes a repeated call idempotent AND honest ([N-19]).
  defp revoke_by(conn, column, value) do
    sql =
      "UPDATE refresh_tokens SET status = 'revoked' " <>
        "WHERE #{column} = $1 AND status <> 'revoked'"

    case query(conn, sql, [value]) do
      {:ok, %{num_rows: n}} -> {:ok, n}
      {:error, reason} -> {:error, reason}
    end
  end

  defp to_record([sel, vh, kid, fam, gen, uid, dev, cat, fexp, iexp, status, rot, rep]) do
    %Record{
      selector: sel,
      verifier_hash: vh,
      kid: kid,
      family_id: fam,
      generation: gen,
      user_id: uid,
      device_id_hash: dev,
      created_at: cat,
      family_expires_at: fexp,
      idle_expires_at: iexp,
      # to_existing_atom/1, never to_atom/1: a corrupted column must not be able
      # to grow the atom table.
      status: String.to_existing_atom(status),
      rotated_at: rot,
      replaced_by_selector: rep
    }
  end

  # Non-bang query: a database failure is a value here and a raised
  # NebulaToken.StoreError one layer up ([N-20]).
  defp query(conn, sql, params), do: Postgrex.query(conn, sql, params)
end
