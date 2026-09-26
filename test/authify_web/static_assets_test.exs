defmodule AuthifyWeb.StaticAssetsTest do
  @moduledoc """
  Regression coverage for the production 404s on digested root-level assets.

  `mix phx.digest` rewrites `favicon.svg` to `favicon-<hash>.svg` (and likewise
  for `favicon.ico` / `robots.txt`). `Plug.Static`'s `:only` matches the first
  path segment exactly, so those digested filenames were never served by the
  endpoint. `:only_matching` supplies the required prefix matching.

  These tests exercise the real `AuthifyWeb.Endpoint` pipeline rather than a
  stand-in `Plug.Static` config, so a regression in the endpoint wiring is
  caught.
  """
  use AuthifyWeb.ConnCase, async: false

  @static_dir Path.join(:code.priv_dir(:authify), "static")

  setup do
    created =
      for filename <- ["favicon-probe123.svg", "robots-probe456.txt"] do
        path = Path.join(@static_dir, filename)
        File.write!(path, "probe")
        path
      end

    on_exit(fn -> Enum.each(created, &File.rm/1) end)

    :ok
  end

  test "serves digested root-level assets", %{conn: conn} do
    assert conn |> get("/favicon-probe123.svg") |> Map.get(:status) == 200
    assert conn |> get("/robots-probe456.txt") |> Map.get(:status) == 200
  end

  test "serves undigested root-level assets", %{conn: conn} do
    assert conn |> get("/favicon.svg") |> Map.get(:status) == 200
    assert conn |> get("/robots.txt") |> Map.get(:status) == 200
  end

  test "does not serve unlisted root-level files", %{conn: conn} do
    refute conn |> get("/cache_manifest.json") |> Map.get(:status) == 200
  end
end
