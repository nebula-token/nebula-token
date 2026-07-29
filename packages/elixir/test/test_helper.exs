ExUnit.start()

defmodule NebulaToken.SpecVectors do
  @moduledoc """
  Locates and loads the shared, normative vector files.

  The repository root is found by walking up from this file until a directory
  containing `spec/test-vectors.json` appears. The package therefore hardcodes
  no absolute path and keeps no copy of the vectors: a local copy is exactly how
  a port silently stops testing what the specification publishes ([N-49]).
  """

  @vector_marker Path.join("spec", "test-vectors.json")

  @doc "Repository root — the nearest ancestor directory holding `spec/`."
  @spec root() :: String.t()
  def root, do: walk_up(Path.expand(__DIR__))

  @doc "Absolute path of the `spec/` directory."
  @spec dir() :: String.t()
  def dir, do: Path.join(root(), "spec")

  @doc "Absolute path of a file inside `spec/`."
  @spec path(String.t()) :: String.t()
  def path(name), do: Path.join(dir(), name)

  @doc "Read and decode a vector file from `spec/`."
  @spec load(String.t()) :: map()
  def load(name), do: name |> path() |> File.read!() |> Jason.decode!()

  defp walk_up(directory) do
    cond do
      File.regular?(Path.join(directory, @vector_marker)) ->
        directory

      Path.dirname(directory) == directory ->
        raise "#{@vector_marker} not found in any ancestor of #{__DIR__}"

      true ->
        walk_up(Path.dirname(directory))
    end
  end
end
