defmodule Authify.ScopesTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Authify.Scopes

  describe "oauth_scopes/0" do
    test "includes the standard OIDC scopes" do
      scopes = Scopes.oauth_scopes()
      assert "openid" in scopes
      assert "profile" in scopes
      assert "email" in scopes
      assert "phone" in scopes
      assert "groups" in scopes
    end

    test "does not include management API scopes" do
      scopes = Scopes.oauth_scopes()
      refute "users:read" in scopes
      refute "profile:read" in scopes
    end
  end

  describe "management_api_scopes/0" do
    test "includes user management scopes" do
      scopes = Scopes.management_api_scopes()
      assert "users:read" in scopes
      assert "users:write" in scopes
    end

    test "includes application management scopes" do
      scopes = Scopes.management_api_scopes()
      assert "applications:read" in scopes
      assert "applications:write" in scopes
    end

    test "includes audit log scope" do
      assert "audit_logs:read" in Scopes.management_api_scopes()
    end

    test "does not include OAuth/OIDC scopes" do
      scopes = Scopes.management_api_scopes()
      refute "openid" in scopes
      refute "profile" in scopes
    end

    test "does not include PAT-only scopes" do
      scopes = Scopes.management_api_scopes()
      refute "profile:read" in scopes
      refute "profile:write" in scopes
    end
  end

  describe "pat_only_scopes/0" do
    test "returns profile:read and profile:write" do
      scopes = Scopes.pat_only_scopes()
      assert "profile:read" in scopes
      assert "profile:write" in scopes
    end

    test "contains exactly the PAT-only scopes" do
      assert length(Scopes.pat_only_scopes()) == 2
    end
  end

  describe "scim_scopes/0" do
    test "includes broad SCIM scopes" do
      scopes = Scopes.scim_scopes()
      assert "scim:read" in scopes
      assert "scim:write" in scopes
    end

    test "includes resource-specific SCIM scopes" do
      scopes = Scopes.scim_scopes()
      assert "scim:users:read" in scopes
      assert "scim:users:write" in scopes
      assert "scim:groups:read" in scopes
      assert "scim:groups:write" in scopes
    end

    test "includes self-service SCIM scopes" do
      scopes = Scopes.scim_scopes()
      assert "scim:me" in scopes
      assert "scim:me:write" in scopes
    end
  end

  describe "pat_scopes/0" do
    test "includes all management API scopes" do
      pat = Scopes.pat_scopes()

      for scope <- Scopes.management_api_scopes() do
        assert scope in pat
      end
    end

    test "includes PAT-only scopes" do
      pat = Scopes.pat_scopes()
      assert "profile:read" in pat
      assert "profile:write" in pat
    end

    test "includes SCIM scopes" do
      pat = Scopes.pat_scopes()
      assert "scim:read" in pat
      assert "scim:write" in pat
    end

    test "does not include OAuth/OIDC scopes" do
      pat = Scopes.pat_scopes()
      refute "openid" in pat
      refute "profile" in pat
    end
  end

  describe "all_valid_scopes/0" do
    test "includes OAuth scopes" do
      all = Scopes.all_valid_scopes()
      assert "openid" in all
      assert "profile" in all
    end

    test "includes management API scopes" do
      all = Scopes.all_valid_scopes()
      assert "users:read" in all
    end

    test "includes PAT-only scopes" do
      all = Scopes.all_valid_scopes()
      assert "profile:read" in all
    end

    test "includes SCIM scopes" do
      all = Scopes.all_valid_scopes()
      assert "scim:read" in all
    end
  end

  describe "valid_oauth_scope?/1" do
    test "returns true for valid OAuth scopes" do
      assert Scopes.valid_oauth_scope?("openid")
      assert Scopes.valid_oauth_scope?("profile")
      assert Scopes.valid_oauth_scope?("email")
      assert Scopes.valid_oauth_scope?("phone")
      assert Scopes.valid_oauth_scope?("groups")
    end

    test "returns false for management API scopes" do
      refute Scopes.valid_oauth_scope?("users:read")
      refute Scopes.valid_oauth_scope?("applications:write")
    end

    test "returns false for PAT-only scopes" do
      refute Scopes.valid_oauth_scope?("profile:read")
      refute Scopes.valid_oauth_scope?("profile:write")
    end

    test "returns false for unknown scopes" do
      refute Scopes.valid_oauth_scope?("nonexistent")
      refute Scopes.valid_oauth_scope?("")
    end
  end

  describe "valid_management_api_scope?/1" do
    test "returns true for valid management API scopes" do
      assert Scopes.valid_management_api_scope?("users:read")
      assert Scopes.valid_management_api_scope?("applications:write")
      assert Scopes.valid_management_api_scope?("audit_logs:read")
    end

    test "returns false for OAuth scopes" do
      refute Scopes.valid_management_api_scope?("openid")
      refute Scopes.valid_management_api_scope?("profile")
    end

    test "returns false for PAT-only scopes" do
      refute Scopes.valid_management_api_scope?("profile:read")
    end

    test "returns false for unknown scopes" do
      refute Scopes.valid_management_api_scope?("nonexistent")
    end
  end

  describe "valid_scope?/1" do
    test "returns true for OAuth scopes" do
      assert Scopes.valid_scope?("openid")
      assert Scopes.valid_scope?("profile")
    end

    test "returns true for management API scopes" do
      assert Scopes.valid_scope?("users:read")
      assert Scopes.valid_scope?("applications:write")
    end

    test "returns true for PAT-only scopes" do
      assert Scopes.valid_scope?("profile:read")
      assert Scopes.valid_scope?("profile:write")
    end

    test "returns true for SCIM scopes" do
      assert Scopes.valid_scope?("scim:read")
      assert Scopes.valid_scope?("scim:me")
    end

    test "returns false for unknown scopes" do
      refute Scopes.valid_scope?("nonexistent")
      refute Scopes.valid_scope?("")
      refute Scopes.valid_scope?("admin")
    end
  end

  describe "scopes_by_category/0" do
    test "returns a map" do
      assert is_map(Scopes.scopes_by_category())
    end

    test "contains expected top-level categories" do
      categories = Map.keys(Scopes.scopes_by_category())
      assert "OAuth/OIDC" in categories
      assert "User Management" in categories
      assert "SCIM 2.0 Provisioning" in categories
      assert "Profile" in categories
    end

    test "each category value is a list of {scope, description} tuples" do
      Scopes.scopes_by_category()
      |> Enum.each(fn {_category, entries} ->
        assert is_list(entries)

        Enum.each(entries, fn entry ->
          assert {scope, description} = entry
          assert is_binary(scope)
          assert is_binary(description)
        end)
      end)
    end

    test "all scopes in the map are valid scopes" do
      Scopes.scopes_by_category()
      |> Enum.flat_map(fn {_cat, entries} -> Enum.map(entries, &elem(&1, 0)) end)
      |> Enum.each(fn scope ->
        assert Scopes.valid_scope?(scope), "#{scope} in scopes_by_category is not a valid scope"
      end)
    end
  end
end
