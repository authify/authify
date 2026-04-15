defmodule Authify.OAuthTest do
  use Authify.DataCase, async: true

  alias Authify.Accounts
  alias Authify.OAuth
  import Authify.AccountsFixtures
  import Authify.OAuthFixtures

  describe "applications" do
    alias Authify.OAuth.Application

    import Authify.OAuthFixtures

    @invalid_attrs %{
      name: nil,
      description: nil,
      scopes: nil,
      redirect_uris: nil,
      organization_id: nil
    }

    test "list_applications/1 returns all applications for an organization" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      applications = OAuth.list_applications(organization)
      assert length(applications) == 1
      assert hd(applications).id == application.id
    end

    test "get_application!/2 returns the application with given id and organization" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      found_application = OAuth.get_application!(application.id, organization)
      assert found_application.id == application.id
      assert found_application.name == application.name
      assert found_application.organization_id == organization.id
    end

    test "create_application/1 with valid data creates a application" do
      organization = organization_fixture()

      valid_attrs = %{
        name: "some name",
        description: "some description",
        scopes: "openid profile email",
        redirect_uris: "https://example.com/callback",
        organization_id: organization.id
      }

      assert {:ok, %Application{} = application} = OAuth.create_application(valid_attrs)
      assert application.name == "some name"
      assert application.description == "some description"
      assert Application.scopes_list(application) == ["openid", "profile", "email"]
      assert application.redirect_uris == "https://example.com/callback"
      assert application.organization_id == organization.id
      assert is_binary(application.client_id)
      assert is_binary(application.client_secret)
    end

    test "create_application/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = OAuth.create_application(@invalid_attrs)
    end

    test "update_application/2 with valid data updates the application" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)

      update_attrs = %{
        name: "some updated name",
        description: "some updated description",
        scopes: "openid profile",
        redirect_uris: "https://updated.example.com/callback"
      }

      assert {:ok, %Application{} = updated_application} =
               OAuth.update_application(application, update_attrs)

      assert updated_application.name == "some updated name"
      assert updated_application.description == "some updated description"
      assert Application.scopes_list(updated_application) == ["openid", "profile"]
      assert updated_application.redirect_uris == "https://updated.example.com/callback"
      # Client credentials should not change during update
      assert updated_application.client_id == application.client_id
      assert updated_application.client_secret == application.client_secret
    end

    test "update_application/2 with invalid data returns error changeset" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      assert {:error, %Ecto.Changeset{}} = OAuth.update_application(application, @invalid_attrs)
      found_application = OAuth.get_application!(application.id, organization)
      assert found_application.id == application.id
      assert found_application.name == application.name
    end

    test "delete_application/1 deletes the application" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      assert {:ok, %Application{}} = OAuth.delete_application(application)

      assert_raise Ecto.NoResultsError, fn ->
        OAuth.get_application!(application.id, organization)
      end
    end

    test "change_application/1 returns a application changeset" do
      organization = organization_fixture()
      application = application_fixture(organization: organization)
      assert %Ecto.Changeset{} = OAuth.change_application(application)
    end
  end

  describe "user grants" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      app = application_fixture(organization: org)
      %{org: org, user: user, app: app}
    end

    test "create_or_update_user_grant/3 creates new grant", %{user: user, app: app} do
      assert {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])

      assert grant.user_id == user.id
      assert grant.application_id == app.id
      assert grant.scopes == "openid profile"
      assert is_nil(grant.revoked_at)
    end

    test "create_or_update_user_grant/3 accepts scopes as string", %{user: user, app: app} do
      assert {:ok, grant} = OAuth.create_or_update_user_grant(user, app, "openid profile email")

      assert grant.scopes == "openid profile email"
    end

    test "create_or_update_user_grant/3 updates existing grant scopes", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      assert grant.scopes == "openid"

      # Update with more scopes
      {:ok, updated_grant} =
        OAuth.create_or_update_user_grant(user, app, ["openid", "profile", "email"])

      assert updated_grant.id == grant.id
      assert updated_grant.scopes == "openid profile email"
    end

    test "create_or_update_user_grant/3 un-revokes revoked grant", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])
      {:ok, revoked_grant} = OAuth.revoke_user_grant(grant)

      assert revoked_grant.revoked_at

      # Re-grant should un-revoke
      {:ok, renewed_grant} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])

      assert renewed_grant.id == grant.id
      assert is_nil(renewed_grant.revoked_at)
      assert renewed_grant.scopes == "openid profile"
    end

    test "get_user_grant/2 returns active grant", %{user: user, app: app} do
      {:ok, created_grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      grant = OAuth.get_user_grant(user, app)

      assert grant.id == created_grant.id
      assert grant.user_id == user.id
      assert grant.application_id == app.id
    end

    test "get_user_grant/2 returns nil for non-existent grant", %{user: user, app: app} do
      assert is_nil(OAuth.get_user_grant(user, app))
    end

    test "get_user_grant/2 returns nil for revoked grant", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])
      {:ok, _} = OAuth.revoke_user_grant(grant)

      assert is_nil(OAuth.get_user_grant(user, app))
    end

    test "list_user_grants/1 returns all active grants for user", %{user: user, org: org} do
      app1 = application_fixture(organization: org, name: "App 1")
      app2 = application_fixture(organization: org, name: "App 2")

      {:ok, _} = OAuth.create_or_update_user_grant(user, app1, ["openid"])
      {:ok, _} = OAuth.create_or_update_user_grant(user, app2, ["openid", "profile"])

      grants = OAuth.list_user_grants(user)

      assert length(grants) == 2
      assert Enum.any?(grants, &(&1.application_id == app1.id))
      assert Enum.any?(grants, &(&1.application_id == app2.id))
    end

    test "list_user_grants/1 excludes revoked grants", %{user: user, org: org} do
      app1 = application_fixture(organization: org, name: "App 1")
      app2 = application_fixture(organization: org, name: "App 2")

      {:ok, grant1} = OAuth.create_or_update_user_grant(user, app1, ["openid"])
      {:ok, _grant2} = OAuth.create_or_update_user_grant(user, app2, ["openid"])

      {:ok, _} = OAuth.revoke_user_grant(grant1)

      grants = OAuth.list_user_grants(user)

      assert length(grants) == 1
      assert hd(grants).application_id == app2.id
    end

    test "list_user_grants/1 orders by most recently updated first", %{user: user, org: org} do
      app1 = application_fixture(organization: org, name: "App 1")
      app2 = application_fixture(organization: org, name: "App 2")

      {:ok, grant1} = OAuth.create_or_update_user_grant(user, app1, ["openid"])
      Process.sleep(10)
      {:ok, _grant2} = OAuth.create_or_update_user_grant(user, app2, ["openid"])

      # Update grant1 to make it most recent
      Process.sleep(10)
      {:ok, _} = OAuth.create_or_update_user_grant(user, app1, ["openid", "profile"])

      grants = OAuth.list_user_grants(user)

      assert hd(grants).id == grant1.id
    end

    test "revoke_user_grant/1 marks grant as revoked", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      assert is_nil(grant.revoked_at)

      {:ok, revoked_grant} = OAuth.revoke_user_grant(grant)

      refute is_nil(revoked_grant.revoked_at)
    end

    test "validate_user_grant/3 succeeds when grant covers all scopes", %{user: user, app: app} do
      {:ok, _} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile", "email"])

      assert {:ok, grant} = OAuth.validate_user_grant(user, app, ["openid", "profile"])
      assert grant.user_id == user.id
    end

    test "validate_user_grant/3 succeeds when scopes exactly match", %{user: user, app: app} do
      {:ok, _} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])

      assert {:ok, _grant} = OAuth.validate_user_grant(user, app, ["openid", "profile"])
    end

    test "validate_user_grant/3 fails with :insufficient_grant when scopes don't match", %{
      user: user,
      app: app
    } do
      {:ok, _} = OAuth.create_or_update_user_grant(user, app, ["openid"])

      assert {:error, :insufficient_grant} =
               OAuth.validate_user_grant(user, app, ["openid", "profile", "email"])
    end

    test "validate_user_grant/3 fails with :no_grant when no grant exists", %{
      user: user,
      app: app
    } do
      assert {:error, :no_grant} = OAuth.validate_user_grant(user, app, ["openid"])
    end

    test "validate_user_grant/3 fails when grant is revoked", %{user: user, app: app} do
      {:ok, grant} = OAuth.create_or_update_user_grant(user, app, ["openid", "profile"])
      {:ok, _} = OAuth.revoke_user_grant(grant)

      assert {:error, :no_grant} = OAuth.validate_user_grant(user, app, ["openid"])
    end
  end

  describe "generate_userinfo_claims/2 with extended profile fields" do
    setup do
      org = organization_fixture()
      user = user_for_organization_fixture(org)

      {:ok, user} =
        Accounts.update_user(user, %{
          "locale" => "en-GB",
          "zoneinfo" => "Europe/London",
          "website" => "https://example.co.uk",
          "team" => "DevOps",
          "title" => "DevOps Engineer",
          "avatar_url" => "https://cdn.example.com/avatar.jpg",
          "phone_number" => "+441234567890",
          "phone_number_verified" => true
        })

      %{user: user}
    end

    test "profile scope includes picture, locale, zoneinfo, website, team, title", %{user: user} do
      claims = OAuth.generate_userinfo_claims(user, ["profile"])

      assert claims["locale"] == "en-GB"
      assert claims["zoneinfo"] == "Europe/London"
      assert claims["website"] == "https://example.co.uk"
      assert claims["team"] == "DevOps"
      assert claims["title"] == "DevOps Engineer"
      assert claims["picture"] == "https://cdn.example.com/avatar.jpg"
    end

    test "phone scope includes phone_number and phone_number_verified", %{user: user} do
      claims = OAuth.generate_userinfo_claims(user, ["phone"])

      assert claims["phone_number"] == "+441234567890"
      assert claims["phone_number_verified"] == true
    end

    test "profile scope omits nil fields" do
      org = organization_fixture()
      sparse_user = user_for_organization_fixture(org)

      claims = OAuth.generate_userinfo_claims(sparse_user, ["profile"])

      refute Map.has_key?(claims, "locale")
      refute Map.has_key?(claims, "zoneinfo")
      refute Map.has_key?(claims, "website")
      refute Map.has_key?(claims, "team")
      refute Map.has_key?(claims, "title")
    end

    test "phone scope omits phone_number when nil" do
      org = organization_fixture()
      sparse_user = user_for_organization_fixture(org)

      claims = OAuth.generate_userinfo_claims(sparse_user, ["phone"])

      refute Map.has_key?(claims, "phone_number")
    end

    test "phone scope returns phone_number_verified false when unset" do
      org = organization_fixture()

      {:ok, user_with_phone} =
        Accounts.update_user(user_for_organization_fixture(org), %{
          "phone_number" => "+10000000000"
        })

      claims = OAuth.generate_userinfo_claims(user_with_phone, ["phone"])

      assert claims["phone_number"] == "+10000000000"
      assert claims["phone_number_verified"] == false
    end

    test "profile scope falls back to Gravatar URL when avatar_url is nil" do
      org = organization_fixture()
      user = user_for_organization_fixture(org)
      user = Authify.Repo.preload(user, :emails)

      assert is_nil(user.avatar_url)

      claims = OAuth.generate_userinfo_claims(user, ["profile"])

      assert is_binary(claims["picture"])
      assert String.starts_with?(claims["picture"], "https://www.gravatar.com/avatar/")
    end
  end

  describe "refresh_tokens nonce" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)
      %{organization: organization, user: user, application: application}
    end

    test "create_refresh_token stores nonce when provided", %{
      application: application,
      user: user
    } do
      {:ok, rt} =
        OAuth.create_refresh_token(application, user, "openid profile", nil, "nonce_abc")

      assert rt.nonce == "nonce_abc"
    end

    test "create_refresh_token stores nil nonce when not provided", %{
      application: application,
      user: user
    } do
      {:ok, rt} = OAuth.create_refresh_token(application, user, "openid profile")
      assert is_nil(rt.nonce)
    end

    test "exchange_authorization_code propagates nonce to refresh token", %{
      application: application,
      user: user
    } do
      {:ok, auth_code} =
        OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"],
          %{nonce: "propagate_me"}
        )

      {:ok, result} = OAuth.exchange_authorization_code(auth_code, application)
      assert result.refresh_token.nonce == "propagate_me"
    end

    test "exchange_authorization_code propagates nil nonce when not set", %{
      application: application,
      user: user
    } do
      {:ok, auth_code} =
        OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      {:ok, result} = OAuth.exchange_authorization_code(auth_code, application)
      assert is_nil(result.refresh_token.nonce)
    end

    test "exchange_refresh_token preserves nonce in rotated refresh token", %{
      application: application,
      user: user
    } do
      {:ok, auth_code} =
        OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"],
          %{nonce: "rotation_nonce"}
        )

      {:ok, result} = OAuth.exchange_authorization_code(auth_code, application)
      original_rt = result.refresh_token

      {:ok, rotated} = OAuth.exchange_refresh_token(original_rt)
      assert rotated.refresh_token.nonce == "rotation_nonce"
    end
  end

  describe "authorization_codes nonce" do
    setup do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      application = application_fixture(organization: organization)
      %{organization: organization, user: user, application: application}
    end

    test "create_authorization_code stores nonce when provided", %{
      application: application,
      user: user
    } do
      {:ok, auth_code} =
        OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"],
          %{nonce: "my_test_nonce"}
        )

      assert auth_code.nonce == "my_test_nonce"
    end

    test "create_authorization_code stores nil nonce when not provided", %{
      application: application,
      user: user
    } do
      {:ok, auth_code} =
        OAuth.create_authorization_code(
          application,
          user,
          "https://example.com/callback",
          ["openid", "profile"]
        )

      assert is_nil(auth_code.nonce)
    end
  end
end
