defmodule AuthifyWeb.API.DocsControllerTest do
  use AuthifyWeb.ConnCase, async: true

  describe "GET /docs/openapi.json" do
    test "documents the personal access token lifecycle endpoints", %{conn: conn} do
      spec =
        conn
        |> get("/docs/openapi.json")
        |> json_response(200)

      assert %{
               "get" => %{"operationId" => "listPersonalAccessTokens"},
               "post" => %{"operationId" => "createPersonalAccessToken"}
             } = spec["paths"]["/{org_slug}/api/pats"]

      assert %{
               "delete" => %{"operationId" => "revokePersonalAccessToken"}
             } = spec["paths"]["/{org_slug}/api/pats/{id}"]

      assert spec["components"]["schemas"]["PersonalAccessTokenAttributes"]
      assert spec["components"]["schemas"]["PersonalAccessTokenCreateRequest"]
      assert Enum.any?(spec["tags"], &(&1["name"] == "Personal Access Tokens"))
    end
  end
end
