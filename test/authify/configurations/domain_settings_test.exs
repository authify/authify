defmodule Authify.Configurations.DomainSettingsTest do
  use Authify.DataCase, async: true

  alias Authify.Configurations
  alias Authify.Organizations

  import Authify.AccountsFixtures

  setup do
    # Set required tenant_base_domain for all tests
    Configurations.set_global_setting(:tenant_base_domain, "authify.test")
    :ok
  end

  describe "tenant_base_domain global setting" do
    test "can be set and retrieved" do
      assert {:ok, _} =
               Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      value = Configurations.get_global_setting(:tenant_base_domain)
      assert value == "authify.example.com"
    end

    test "validates domain format" do
      assert {:error, reason} =
               Configurations.set_global_setting(:tenant_base_domain, "not a domain!")

      assert reason =~ "must be a valid domain name"
    end

    test "rejects nil value" do
      assert {:error, reason} = Configurations.set_global_setting(:tenant_base_domain, nil)
      assert reason =~ "required and cannot be empty"
    end

    test "rejects empty string" do
      assert {:error, reason} = Configurations.set_global_setting(:tenant_base_domain, "")
      assert reason =~ "required and cannot be empty"
    end

    test "validates maximum domain length" do
      # Domain longer than 253 characters
      long_domain = String.duplicate("a", 250) <> ".com"

      assert {:error, reason} =
               Configurations.set_global_setting(:tenant_base_domain, long_domain)

      assert reason =~ "must be a valid domain name"
    end

    test "accepts valid domain formats" do
      valid_domains = [
        "example.com",
        "authify.example.com",
        "sso-platform.example.com",
        "123.example.com"
      ]

      for domain <- valid_domains do
        assert {:ok, _} = Configurations.set_global_setting(:tenant_base_domain, domain),
               "Expected domain '#{domain}' to be valid"

        assert Configurations.get_global_setting(:tenant_base_domain) == domain
      end
    end
  end

  describe "email_link_domain organization setting" do
    test "can be set to subdomain when tenant_base_domain is configured" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      assert {:ok, _} =
               Configurations.set_organization_setting(
                 org,
                 :email_link_domain,
                 "acme.authify.example.com"
               )

      value = Configurations.get_organization_setting(org, :email_link_domain)
      assert value == "acme.authify.example.com"
    end

    test "can be set to a configured CNAME" do
      org = organization_fixture()
      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})

      assert {:ok, _} =
               Configurations.set_organization_setting(org, :email_link_domain, "sso.acme.com")

      value = Configurations.get_organization_setting(org, :email_link_domain)
      assert value == "sso.acme.com"
    end

    test "rejects domain not in allowed list" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      assert {:error, reason} =
               Configurations.set_organization_setting(
                 org,
                 :email_link_domain,
                 "unauthorized.example.com"
               )

      assert reason =~ "must be one of the allowed domains"
    end

    test "accepts nil value" do
      org = organization_fixture()

      assert {:ok, _} = Configurations.set_organization_setting(org, :email_link_domain, nil)
      assert Configurations.get_organization_setting(org, :email_link_domain) == nil
    end

    test "accepts empty string as nil" do
      org = organization_fixture()

      assert {:ok, _} = Configurations.set_organization_setting(org, :email_link_domain, "")
      assert Configurations.get_organization_setting(org, :email_link_domain) == nil
    end

    test "validation updates when CNAMEs change" do
      org = organization_fixture(slug: "acme")

      {:ok, _cname} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})

      # Set email_link_domain to CNAME
      Configurations.set_organization_setting(org, :email_link_domain, "sso.acme.com")

      # Add tenant base domain - original setting should still be valid
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Should still accept the CNAME
      assert {:ok, _} =
               Configurations.set_organization_setting(org, :email_link_domain, "sso.acme.com")

      # Should now also accept the subdomain
      assert {:ok, _} =
               Configurations.set_organization_setting(
                 org,
                 :email_link_domain,
                 "acme.authify.example.com"
               )
    end
  end

  describe "email_link_domain automatic reset on CNAME deletion" do
    test "resets to default when active CNAME is deleted" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      {:ok, cname} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})

      # Set to CNAME
      Configurations.set_organization_setting(org, :email_link_domain, "sso.acme.com")
      assert Configurations.get_organization_setting(org, :email_link_domain) == "sso.acme.com"

      # Delete the CNAME
      Organizations.delete_cname(cname)

      # Should reset to subdomain
      value = Configurations.get_organization_setting(org, :email_link_domain)
      assert value == "acme.authify.example.com"
    end

    test "does not change setting when different CNAME is deleted" do
      org = organization_fixture()

      {:ok, _cname1} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})

      {:ok, cname2} =
        Organizations.create_cname(%{organization_id: org.id, domain: "auth.acme.com"})

      # Set to first CNAME
      Configurations.set_organization_setting(org, :email_link_domain, "sso.acme.com")

      # Delete second CNAME
      Organizations.delete_cname(cname2)

      # Should remain unchanged
      value = Configurations.get_organization_setting(org, :email_link_domain)
      assert value == "sso.acme.com"
    end

    test "always resets to tenant subdomain, never to CNAMEs" do
      org = organization_fixture(slug: "acme")
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      {:ok, cname1} =
        Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})

      {:ok, _cname2} =
        Organizations.create_cname(%{organization_id: org.id, domain: "auth.acme.com"})

      # Set to first CNAME
      Configurations.set_organization_setting(org, :email_link_domain, "sso.acme.com")

      # Delete the active CNAME
      Organizations.delete_cname(cname1)

      # Should always reset to tenant subdomain, NOT the remaining CNAME
      value = Configurations.get_organization_setting(org, :email_link_domain)
      assert value == "acme.authify.example.com"
      refute value == "auth.acme.com"
    end
  end

  describe "integration: complete domain configuration flow" do
    test "organization can configure domains and email links end-to-end" do
      org = organization_fixture(slug: "acme")

      # Step 1: Admin configures tenant base domain
      Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Step 2: Organization gets default subdomain
      default = Organizations.get_default_domain(org)
      assert default == "acme.authify.example.com"

      # Step 3: Organization adds custom CNAMEs
      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "sso.acme.com"})
      {:ok, _} = Organizations.create_cname(%{organization_id: org.id, domain: "login.acme.com"})

      # Step 4: Check allowed domains
      allowed = Organizations.get_allowed_domains(org)

      assert length(allowed) == 3
      assert "acme.authify.example.com" in allowed
      assert "sso.acme.com" in allowed
      assert "login.acme.com" in allowed

      # Step 5: Set email link domain to custom CNAME
      {:ok, _} =
        Configurations.set_organization_setting(org, :email_link_domain, "login.acme.com")

      value = Configurations.get_organization_setting(org, :email_link_domain)
      assert value == "login.acme.com"

      # Step 6: Verify cannot set to unauthorized domain
      assert {:error, _} =
               Configurations.set_organization_setting(
                 org,
                 :email_link_domain,
                 "hacker.example.com"
               )
    end
  end
end
