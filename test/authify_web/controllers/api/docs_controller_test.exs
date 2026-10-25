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

      delete = spec["paths"]["/{org_slug}/api/pats/{id}"]["delete"]
      assert delete["operationId"] == "revokePersonalAccessToken"
      assert "409" in Map.keys(delete["responses"])

      assert spec["components"]["schemas"]["PersonalAccessTokenAttributes"]
      assert spec["components"]["schemas"]["PersonalAccessTokenCreateRequest"]

      create_properties =
        spec["components"]["schemas"]["PersonalAccessTokenCreateRequest"]["properties"][
          "personal_access_token"
        ]["properties"]

      refute Map.has_key?(create_properties, "user_id")

      refute Enum.any?(
               spec["paths"]["/{org_slug}/api/pats"]["post"]["security"],
               fn requirement ->
                 Map.has_key?(requirement, "OAuth2")
               end
             )

      assert Enum.any?(spec["tags"], &(&1["name"] == "Personal Access Tokens"))
    end
  end
end
