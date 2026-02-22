defmodule AuthifyWeb.OIDCControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  alias Authify.Accounts

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
    test "returns empty JWKS when no OAuth signing cert exists", %{conn: conn} do
      organization = organization_fixture()
      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      assert response["keys"] == []
    end

    test "returns JWK with RSA key from active OAuth signing certificate", %{conn: conn} do
      organization = organization_fixture()

      # Generate an active OAuth signing certificate
      {:ok, cert} =
        Accounts.generate_certificate(organization, %{
          "usage" => "oauth_signing",
          "is_active" => true
        })

      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      assert is_list(response["keys"])
      assert length(response["keys"]) == 1

      [jwk] = response["keys"]
      assert jwk["kty"] == "RSA"
      assert jwk["use"] == "sig"
      assert jwk["alg"] == "RS256"
      assert jwk["kid"] == to_string(cert.id)
      assert is_binary(jwk["n"])
      assert is_binary(jwk["e"])
    end

    test "does not expose SAML signing certificates in JWKS", %{conn: conn} do
      organization = organization_fixture()

      # Generate a SAML signing cert — should NOT appear in JWKS
      {:ok, _saml_cert} =
        Accounts.generate_saml_signing_certificate(organization, %{
          "is_active" => true
        })

      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      # SAML cert is not an OAuth signing cert, so JWKS should be empty
      assert response["keys"] == []
    end

    test "returns empty JWKS when OAuth signing cert is inactive", %{conn: conn} do
      organization = organization_fixture()

      # Generate an inactive OAuth signing cert
      {:ok, _cert} =
        Accounts.generate_certificate(organization, %{
          "usage" => "oauth_signing",
          "is_active" => false
        })

      conn = get(conn, ~p"/#{organization.slug}/.well-known/jwks")
      response = json_response(conn, 200)

      assert response["keys"] == []
    end
  end
end
