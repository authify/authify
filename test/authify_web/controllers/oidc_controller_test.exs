defmodule AuthifyWeb.OIDCControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

  describe "discovery" do
    test "returns organization-scoped OIDC configuration", %{conn: conn} do
      organization = organization_fixture()
      conn = get(conn, ~p"/#{organization.slug}/.well-known/openid-configuration")
      response = json_response(conn, 200)

      base_url = AuthifyWeb.Endpoint.url()
      org_base_url = "#{base_url}/#{organization.slug}"

      # Verify organization-specific URLs
      assert response["issuer"] == org_base_url
      assert response["authorization_endpoint"] == "#{org_base_url}/oauth/authorize"
      assert response["token_endpoint"] == "#{org_base_url}/oauth/token"
      assert response["userinfo_endpoint"] == "#{org_base_url}/oauth/userinfo"
      assert response["jwks_uri"] == "#{org_base_url}/.well-known/jwks"

      # Verify supported features
      assert "code" in response["response_types_supported"]
      assert "RS256" in response["id_token_signing_alg_values_supported"]
      assert "openid" in response["scopes_supported"]
      assert "profile" in response["scopes_supported"]
      assert "email" in response["scopes_supported"]
    end
  end

  describe "jwks" do
    test "returns empty JWKS when no active certificate exists", %{conn: conn} do
      organization = organization_fixture()
      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      assert response["keys"] == []
    end

    test "returns JWK from active signing certificate", %{conn: conn} do
      organization = organization_fixture()

      # Create an active signing certificate
      certificate_fixture(%{
        organization_id: organization.id,
        purpose: "signing",
        is_active: true
      })

      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      assert is_list(response["keys"])
      assert length(response["keys"]) == 1

      [jwk] = response["keys"]
      assert jwk["kty"] == "RSA"
      assert jwk["use"] == "sig"
      assert jwk["alg"] == "RS256"
      assert is_binary(jwk["n"])
      assert is_binary(jwk["e"])
      assert is_binary(jwk["kid"])
    end

    test "does not return expired certificates", %{conn: conn} do
      organization = organization_fixture()

      # Create an expired certificate
      expired_time = DateTime.add(DateTime.utc_now(), -1, :day)

      certificate_fixture(%{
        organization_id: organization.id,
        purpose: "signing",
        is_active: true,
        expires_at: expired_time
      })

      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      # Should be empty since certificate is expired
      assert response["keys"] == []
    end

    test "does not return inactive certificates", %{conn: conn} do
      organization = organization_fixture()

      # Create an inactive certificate
      certificate_fixture(%{
        organization_id: organization.id,
        purpose: "signing",
        is_active: false
      })

      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      # Should be empty since certificate is not active
      assert response["keys"] == []
    end
  end
end
