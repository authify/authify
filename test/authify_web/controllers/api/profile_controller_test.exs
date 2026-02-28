defmodule AuthifyWeb.API.ProfileControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias Authify.Accounts

  defp setup_pat_conn(conn, user, organization, scopes \\ "profile:read profile:write") do
    {:ok, token} =
      Accounts.create_personal_access_token(user, organization, %{
        "name" => "Test API Token",
        "scopes" => scopes
      })

    conn
    |> put_req_header("accept", "application/vnd.authify.v1+json")
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer #{token.plaintext_token}")
  end

  describe "GET /api/profile" do
    test "returns profile with extended fields when set", %{conn: conn} do
      user = user_fixture()
      organization = Accounts.get_organization!(user.organization_id)

      {:ok, user} =
        Accounts.update_user(user, %{
          "locale" => "ja-JP",
          "zoneinfo" => "Asia/Tokyo",
          "phone_number" => "+81312345678",
          "website" => "https://mysite.jp",
          "avatar_url" => "https://cdn.example.jp/avatar.jpg",
          "team" => "Engineering",
          "title" => "Software Engineer"
        })

      conn = setup_pat_conn(conn, user, organization, "profile:read")

      response = json_response(get(conn, "/#{organization.slug}/api/profile"), 200)
      attrs = response["data"]["attributes"]

      assert attrs["locale"] == "ja-JP"
      assert attrs["zoneinfo"] == "Asia/Tokyo"
      assert attrs["phone_number"] == "+81312345678"
      assert attrs["website"] == "https://mysite.jp"
      assert attrs["avatar_url"] == "https://cdn.example.jp/avatar.jpg"
      assert attrs["team"] == "Engineering"
      assert attrs["title"] == "Software Engineer"
    end
  end

  describe "PATCH /api/profile" do
    test "updates user-editable extended profile fields", %{conn: conn} do
      user = user_fixture()
      organization = Accounts.get_organization!(user.organization_id)
      conn = setup_pat_conn(conn, user, organization)

      params = %{
        "user" => %{
          "locale" => "pt-BR",
          "zoneinfo" => "America/Sao_Paulo",
          "phone_number" => "+5511987654321",
          "website" => "https://meusite.com.br",
          "avatar_url" => "https://cdn.example.com.br/me.jpg"
        }
      }

      response = json_response(put(conn, "/#{organization.slug}/api/profile", params), 200)
      attrs = response["data"]["attributes"]

      assert attrs["locale"] == "pt-BR"
      assert attrs["zoneinfo"] == "America/Sao_Paulo"
      assert attrs["phone_number"] == "+5511987654321"
      assert attrs["website"] == "https://meusite.com.br"
      assert attrs["avatar_url"] == "https://cdn.example.com.br/me.jpg"
    end

    test "does not allow team or title via profile API", %{conn: conn} do
      user = user_fixture()
      organization = Accounts.get_organization!(user.organization_id)
      conn = setup_pat_conn(conn, user, organization)

      params = %{
        "user" => %{
          "first_name" => "Charlie",
          "team" => "HACKED",
          "title" => "CEO"
        }
      }

      response = json_response(put(conn, "/#{organization.slug}/api/profile", params), 200)
      attrs = response["data"]["attributes"]

      assert attrs["first_name"] == "Charlie"
      refute Map.get(attrs, "team") == "HACKED"
      refute Map.get(attrs, "title") == "CEO"
    end

    test "does not allow phone_number_verified via profile API", %{conn: conn} do
      user = user_fixture()
      organization = Accounts.get_organization!(user.organization_id)
      conn = setup_pat_conn(conn, user, organization)

      params = %{"user" => %{"phone_number_verified" => true}}
      json_response(put(conn, "/#{organization.slug}/api/profile", params), 200)

      updated = Accounts.get_user!(user.id)
      assert updated.phone_number_verified == false
    end

    test "returns validation error for invalid avatar_url", %{conn: conn} do
      user = user_fixture()
      organization = Accounts.get_organization!(user.organization_id)
      conn = setup_pat_conn(conn, user, organization)

      params = %{"user" => %{"avatar_url" => "not-a-valid-url"}}
      response = json_response(put(conn, "/#{organization.slug}/api/profile", params), 422)

      assert response["error"]["type"] == "validation_failed"
    end
  end
end
