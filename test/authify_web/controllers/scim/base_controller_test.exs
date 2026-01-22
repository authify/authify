defmodule AuthifyWeb.SCIM.BaseControllerTest do
  use AuthifyWeb.ConnCase, async: true

  alias AuthifyWeb.SCIM.BaseController

  describe "render_scim_resource/3" do
    test "renders SCIM resource with default status 200", %{conn: conn} do
      resource = %{
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        id: "123",
        userName: "jsmith"
      }

      conn = BaseController.render_scim_resource(conn, resource)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 200)
      assert response["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
      assert response["id"] == "123"
      assert response["userName"] == "jsmith"
    end

    test "renders SCIM resource with custom status", %{conn: conn} do
      resource = %{
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        id: "456",
        userName: "jdoe"
      }

      conn = BaseController.render_scim_resource(conn, resource, status: 201)

      assert conn.status == 201
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 201)
      assert response["id"] == "456"
    end
  end

  describe "render_scim_list/6" do
    test "renders SCIM ListResponse with resources", %{conn: conn} do
      resources = [
        %{id: "1", userName: "user1"},
        %{id: "2", userName: "user2"},
        %{id: "3", userName: "user3"}
      ]

      conn = BaseController.render_scim_list(conn, resources, 10, 1, 25, :user)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 200)
      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
      assert response["totalResults"] == 10
      assert response["itemsPerPage"] == 3
      assert response["startIndex"] == 1
      assert length(response["Resources"]) == 3
    end

    test "renders empty SCIM ListResponse", %{conn: conn} do
      conn = BaseController.render_scim_list(conn, [], 0, 1, 25, :user)

      response = json_response(conn, 200)
      assert response["totalResults"] == 0
      assert response["itemsPerPage"] == 0
      assert response["Resources"] == []
    end

    test "renders paginated SCIM ListResponse", %{conn: conn} do
      resources = [
        %{id: "26", userName: "user26"},
        %{id: "27", userName: "user27"}
      ]

      conn = BaseController.render_scim_list(conn, resources, 100, 26, 25, :user)

      response = json_response(conn, 200)
      assert response["totalResults"] == 100
      assert response["itemsPerPage"] == 2
      assert response["startIndex"] == 26
    end
  end

  describe "render_scim_error/4" do
    test "renders invalid_filter error", %{conn: conn} do
      conn = BaseController.render_scim_error(conn, 400, :invalid_filter, "Invalid filter syntax")

      assert conn.status == 400
      assert get_resp_header(conn, "content-type") == ["application/scim+json; charset=utf-8"]

      response = json_response(conn, 400)
      assert response["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
      assert response["status"] == "400"
      assert response["scimType"] == "invalidFilter"
      assert response["detail"] == "Invalid filter syntax"
    end

    test "renders uniqueness error", %{conn: conn} do
      conn =
        BaseController.render_scim_error(
          conn,
          409,
          :uniqueness,
          "User with externalId 'hr-123' already exists"
        )

      response = json_response(conn, 409)
      assert response["status"] == "409"
      assert response["scimType"] == "uniqueness"
      assert response["detail"] == "User with externalId 'hr-123' already exists"
    end

    test "renders no_target error (404)", %{conn: conn} do
      conn = BaseController.render_scim_error(conn, 404, :no_target, "User not found")

      response = json_response(conn, 404)
      assert response["status"] == "404"
      assert response["scimType"] == "noTarget"
    end

    test "renders mutability error", %{conn: conn} do
      conn =
        BaseController.render_scim_error(
          conn,
          400,
          :mutability,
          "Attribute 'id' is immutable"
        )

      response = json_response(conn, 400)
      assert response["scimType"] == "mutability"
    end

    test "renders invalid_syntax error", %{conn: conn} do
      conn = BaseController.render_scim_error(conn, 400, :invalid_syntax, "Invalid JSON")

      response = json_response(conn, 400)
      assert response["scimType"] == "invalidSyntax"
    end

    test "renders invalid_path error", %{conn: conn} do
      conn = BaseController.render_scim_error(conn, 400, :invalid_path, "Invalid PATCH path")

      response = json_response(conn, 400)
      assert response["scimType"] == "invalidPath"
    end

    test "renders invalid_value error", %{conn: conn} do
      conn =
        BaseController.render_scim_error(conn, 400, :invalid_value, "Invalid attribute value")

      response = json_response(conn, 400)
      assert response["scimType"] == "invalidValue"
    end

    test "renders too_many error", %{conn: conn} do
      conn = BaseController.render_scim_error(conn, 400, :too_many, "Too many results")

      response = json_response(conn, 400)
      assert response["scimType"] == "tooMany"
    end

    test "renders error with string scim_type", %{conn: conn} do
      conn = BaseController.render_scim_error(conn, 400, "customError", "Custom error message")

      response = json_response(conn, 400)
      assert response["scimType"] == "customError"
    end
  end

  describe "ensure_scim_scope/2" do
    test "returns :ok when token has required scope", %{conn: conn} do
      conn = assign(conn, :current_scopes, ["scim:read", "scim:write"])

      assert {:ok, ^conn} = BaseController.ensure_scim_scope(conn, "scim:read")
    end

    test "returns :ok when token has write scope for read request", %{conn: conn} do
      conn = assign(conn, :current_scopes, ["scim:users:write"])

      assert {:ok, ^conn} = BaseController.ensure_scim_scope(conn, "scim:users:read")
    end

    test "returns :error when token lacks required scope", %{conn: conn} do
      conn = assign(conn, :current_scopes, ["scim:read"])

      assert {:error, :unauthorized} = BaseController.ensure_scim_scope(conn, "scim:write")
    end

    test "returns :error when no scopes present", %{conn: conn} do
      assert {:error, :unauthorized} = BaseController.ensure_scim_scope(conn, "scim:read")
    end

    test "returns :error when token has empty scopes", %{conn: conn} do
      conn = assign(conn, :current_scopes, [])

      assert {:error, :unauthorized} = BaseController.ensure_scim_scope(conn, "scim:read")
    end

    test "supports hierarchical scopes - write includes read", %{conn: conn} do
      conn = assign(conn, :current_scopes, ["scim:write"])

      assert {:ok, ^conn} = BaseController.ensure_scim_scope(conn, "scim:read")
    end

    test "supports resource-level scopes", %{conn: conn} do
      conn = assign(conn, :current_scopes, ["scim:users:write"])

      # Write includes read for same resource
      assert {:ok, ^conn} = BaseController.ensure_scim_scope(conn, "scim:users:read")

      # But not for different resource
      assert {:error, :unauthorized} = BaseController.ensure_scim_scope(conn, "scim:groups:read")
    end

    test "exact scope match works", %{conn: conn} do
      conn = assign(conn, :current_scopes, ["scim:users:read"])

      assert {:ok, ^conn} = BaseController.ensure_scim_scope(conn, "scim:users:read")
    end

    test "write scope does not match different resource read", %{conn: conn} do
      conn = assign(conn, :current_scopes, ["scim:users:write"])

      assert {:error, :unauthorized} = BaseController.ensure_scim_scope(conn, "scim:groups:write")
    end
  end
end
