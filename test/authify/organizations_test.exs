defmodule Authify.OrganizationsTest do
  use Authify.DataCase, async: true

  alias Authify.Configurations
  alias Authify.Organizations
  alias Authify.Organizations.OrganizationCname
  import Authify.AccountsFixtures

  setup do
    # Set required tenant_base_domain for all tests
    Configurations.set_global_setting(:tenant_base_domain, "authify.test")
    :ok
  end

  describe "list_organization_cnames/1" do
    test "returns all CNAMEs for an organization" do
      org = organization_fixture()
      other_org = organization_fixture()

      {:ok, cname1} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      {:ok, cname2} =
        Organizations.create_cname(%{organization_id: org.id, domain: "auth.example.com"})

      # CNAME for different org shouldn't appear
      {:ok, _other_cname} =
        Organizations.create_cname(%{organization_id: other_org.id, domain: "other.example.com"})

      cnames = Organizations.list_organization_cnames(org)

      assert length(cnames) == 2
      assert Enum.any?(cnames, &(&1.id == cname1.id))
      assert Enum.any?(cnames, &(&1.id == cname2.id))
    end

    test "returns empty list when org has no CNAMEs" do
      org = organization_fixture()
      assert Organizations.list_organization_cnames(org) == []
    end

    test "returns CNAMEs sorted by domain" do
      org = organization_fixture()

      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "zzz.example.com"})
      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "aaa.example.com"})
      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "mmm.example.com"})

      cnames = Organizations.list_organization_cnames(org)

      assert Enum.map(cnames, & &1.domain) == [
               "aaa.example.com",
               "mmm.example.com",
               "zzz.example.com"
             ]
    end
  end

  describe "get_cname!/1" do
    test "returns the CNAME with given id" do
      org = organization_fixture()

      {:ok, cname} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      found = Organizations.get_cname!(cname.id)
      assert found.id == cname.id
      assert found.domain == "sso.example.com"
    end

    test "raises when CNAME not found" do
      assert_raise Ecto.NoResultsError, fn ->
        Organizations.get_cname!(999_999)
      end
    end
  end

  describe "create_cname/1" do
    test "creates a CNAME with valid data" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        domain: "sso.example.com"
      }

      assert {:ok, %OrganizationCname{} = cname} = Organizations.create_cname(attrs)
      assert cname.domain == "sso.example.com"
      assert cname.organization_id == org.id
      assert cname.verified == false
    end

    test "returns error changeset with invalid data" do
      assert {:error, %Ecto.Changeset{}} = Organizations.create_cname(%{domain: "invalid domain"})
    end

    test "enforces unique domain constraint" do
      org1 = organization_fixture()
      org2 = organization_fixture()

      {:ok, _} =
        Organizations.create_cname(%{organization_id: org1.id, domain: "sso.example.com"})

      assert {:error, changeset} =
               Organizations.create_cname(%{organization_id: org2.id, domain: "sso.example.com"})

      assert "This domain is already in use by another organization" in errors_on(changeset).domain
    end
  end

  describe "update_cname/2" do
    test "updates the CNAME with valid data" do
      org = organization_fixture()

      {:ok, cname} =
        Organizations.create_cname(%{organization_id: org.id, domain: "old.example.com"})

      assert {:ok, %OrganizationCname{} = updated} =
               Organizations.update_cname(cname, %{domain: "new.example.com"})

      assert updated.domain == "new.example.com"
    end

    test "returns error changeset with invalid data" do
      org = organization_fixture()

      {:ok, cname} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      assert {:error, %Ecto.Changeset{}} =
               Organizations.update_cname(cname, %{domain: "invalid domain"})
    end
  end

  describe "delete_cname/1" do
    test "deletes the CNAME" do
      org = organization_fixture()

      {:ok, cname} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      assert {:ok, %OrganizationCname{}} = Organizations.delete_cname(cname)
      assert_raise Ecto.NoResultsError, fn -> Organizations.get_cname!(cname.id) end
    end

    test "resets email_link_domain if it was using the deleted domain" do
      org = organization_fixture(slug: "test-org")

      # Create CNAMEs
      {:ok, cname1} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      {:ok, _cname2} =
        Organizations.create_cname(%{organization_id: org.id, domain: "auth.example.com"})

      # Set email_link_domain to first CNAME
      Configurations.set_organization_setting(org, :email_link_domain, "sso.example.com")

      current = Configurations.get_organization_setting(org, :email_link_domain)
      assert current == "sso.example.com"

      # Delete the CNAME that's being used
      {:ok, _} = Organizations.delete_cname(cname1)

      # email_link_domain should be reset to tenant subdomain
      updated = Configurations.get_organization_setting(org, :email_link_domain)
      assert updated == "test-org.authify.test"
    end

    test "does not reset email_link_domain if it's using a different domain" do
      org = organization_fixture()

      {:ok, cname1} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      {:ok, _cname2} =
        Organizations.create_cname(%{organization_id: org.id, domain: "auth.example.com"})

      # Set email_link_domain to second CNAME
      Configurations.set_organization_setting(org, :email_link_domain, "auth.example.com")

      # Delete the first CNAME
      {:ok, _} = Organizations.delete_cname(cname1)

      # email_link_domain should remain unchanged
      current = Configurations.get_organization_setting(org, :email_link_domain)
      assert current == "auth.example.com"
    end
  end

  describe "get_allowed_domains/1" do
    test "returns subdomain when tenant_base_domain is configured" do
      org = organization_fixture(slug: "acme")

      # Set tenant base domain
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      allowed = Organizations.get_allowed_domains(org)

      assert "acme.authify.example.com" in allowed
    end

    test "includes all CNAMEs in allowed domains" do
      org = organization_fixture()

      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      {:ok, _} =
        Organizations.create_cname(%{organization_id: org.id, domain: "auth.example.com"})

      allowed = Organizations.get_allowed_domains(org)

      assert "sso.example.com" in allowed
      assert "auth.example.com" in allowed
    end
  end

  describe "get_default_domain/1" do
    test "returns subdomain based on tenant_base_domain" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      assert Organizations.get_default_domain(org) == "acme.authify.example.com"
    end

    test "always uses tenant_base_domain even when CNAMEs exist" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.test")

      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "sso.example.com"})

      {:ok, _} =
        Organizations.create_cname(%{organization_id: org.id, domain: "auth.example.com"})

      # Should return subdomain, NOT a CNAME
      assert Organizations.get_default_domain(org) == "acme.authify.test"
    end
  end

  describe "change_cname/2" do
    test "returns a changeset for a CNAME" do
      cname = %OrganizationCname{}
      assert %Ecto.Changeset{} = Organizations.change_cname(cname)
    end
  end

  describe "get_email_link_domain/1" do
    test "returns configured email_link_domain when set" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})

      # Set custom domain
      Configurations.set_organization_setting(org, :email_link_domain, "sso.acme.com")

      assert Organizations.get_email_link_domain(org) == "sso.acme.com"
    end

    test "falls back to default subdomain when email_link_domain not set" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      assert Organizations.get_email_link_domain(org) == "acme.authify.example.com"
    end

    test "falls back to subdomain even when CNAMEs exist" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.test")

      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})

      # Should fall back to subdomain, not CNAME
      assert Organizations.get_email_link_domain(org) == "acme.authify.test"
    end

    test "treats empty string as unset and falls back to default" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      Configurations.set_organization_setting(org, :email_link_domain, "")

      assert Organizations.get_email_link_domain(org) == "acme.authify.example.com"
    end
  end
end
