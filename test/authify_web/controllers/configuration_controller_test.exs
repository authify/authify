defmodule AuthifyWeb.ConfigurationControllerTest do
  use AuthifyWeb.ConnCase

  import Authify.AccountsFixtures

  describe "show" do
    test "shows global configuration for authify-global organization", %{conn: conn} do
      global_org = Authify.Accounts.get_global_organization()
      admin = user_fixture(%{organization: global_org, role: "admin"})

      conn =
        conn
        |> log_in_user(admin)
        |> get(~p"/#{global_org.slug}/settings/configuration")

      assert html_response(conn, 200) =~ "Global Settings"
      assert html_response(conn, 200) =~ "Allow Organization Registration"
      assert html_response(conn, 200) =~ "Site Name"
      assert html_response(conn, 200) =~ "Support Email"
    end

    test "shows organization configuration for tenant organization", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      conn =
        conn
        |> log_in_user(admin)
        |> get(~p"/#{organization.slug}/settings/configuration")

      assert html_response(conn, 200) =~ "Organization Settings"
      assert html_response(conn, 200) =~ "Allow Invitations"
      assert html_response(conn, 200) =~ "Enable SAML"
      assert html_response(conn, 200) =~ "Enable OAuth2/OIDC"
    end
  end

  describe "update" do
    test "updates global configuration and shows success message", %{conn: conn} do
      global_org = Authify.Accounts.get_global_organization()
      admin = user_fixture(%{organization: global_org, role: "admin"})

      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{global_org.slug}/settings/configuration", %{
          "settings" => %{
            "site_name" => "My Custom Authify",
            "support_email" => "help@example.com",
            "allow_organization_registration" => "true"
          }
        })

      assert redirected_to(conn) == ~p"/#{global_org.slug}/settings/configuration"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) == "Configuration updated successfully."

      # Verify settings were saved
      assert Authify.Configurations.get_setting("Organization", global_org.id, :site_name) ==
               "My Custom Authify"

      assert Authify.Configurations.get_setting("Organization", global_org.id, :support_email) ==
               "help@example.com"

      assert Authify.Configurations.get_setting(
               "Organization",
               global_org.id,
               :allow_organization_registration
             ) == true
    end

    test "unchecking boolean settings sets them to false (global)", %{conn: conn} do
      global_org = Authify.Accounts.get_global_organization()
      admin = user_fixture(%{organization: global_org, role: "admin"})

      # First, enable the setting
      Authify.Configurations.set_setting(
        "Organization",
        global_org.id,
        :allow_organization_registration,
        true
      )

      # Now submit form WITHOUT the checkbox (it should be set to false)
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{global_org.slug}/settings/configuration", %{
          "settings" => %{
            "site_name" => "Test Site"
            # allow_organization_registration not included = unchecked
          }
        })

      assert redirected_to(conn) == ~p"/#{global_org.slug}/settings/configuration"

      # Verify the boolean was set to false
      assert Authify.Configurations.get_setting(
               "Organization",
               global_org.id,
               :allow_organization_registration
             ) == false
    end

    test "updates organization configuration for tenant organizations", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "settings" => %{
            "allow_invitations" => "true",
            "allow_saml" => "true",
            "allow_oauth" => "false",
            "description" => "Test organization",
            "website_url" => "https://example.com",
            "contact_email" => "contact@example.com"
          }
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) == "Configuration updated successfully."

      # Verify settings were saved
      assert Authify.Configurations.get_setting(
               "Organization",
               organization.id,
               :allow_invitations
             ) ==
               true

      assert Authify.Configurations.get_setting("Organization", organization.id, :allow_saml) ==
               true

      assert Authify.Configurations.get_setting("Organization", organization.id, :allow_oauth) ==
               false

      assert Authify.Configurations.get_setting("Organization", organization.id, :description) ==
               "Test organization"
    end

    test "unchecking boolean settings sets them to false (organization)", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Ensure organization configuration exists before setting values
      Authify.Configurations.get_or_create_configuration(
        "Organization",
        organization.id,
        "organization"
      )

      # First, enable all features
      Authify.Configurations.set_setting(
        "Organization",
        organization.id,
        :allow_invitations,
        true
      )

      Authify.Configurations.set_setting("Organization", organization.id, :allow_saml, true)
      Authify.Configurations.set_setting("Organization", organization.id, :allow_oauth, true)

      # Now submit form with all checkboxes unchecked
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "settings" => %{
            "description" => "Test"
            # No boolean settings included = all unchecked
          }
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"

      # Verify all booleans were set to false
      assert Authify.Configurations.get_setting(
               "Organization",
               organization.id,
               :allow_invitations
             ) ==
               false

      assert Authify.Configurations.get_setting("Organization", organization.id, :allow_saml) ==
               false

      assert Authify.Configurations.get_setting("Organization", organization.id, :allow_oauth) ==
               false
    end

    test "changing authify_domain clears old CNAMEs and creates new one", %{conn: conn} do
      global_org = Authify.Accounts.get_global_organization()
      admin = user_fixture(%{organization: global_org, role: "admin"})

      # Set tenant base domain
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # First, set authify_domain to create initial CNAME
      conn
      |> log_in_user(admin)
      |> patch(~p"/#{global_org.slug}/settings/configuration", %{
        "authify_domain" => "admin.example.com"
      })

      # Verify first CNAME was created
      cnames = Authify.Organizations.list_organization_cnames(global_org)
      assert length(cnames) == 1
      assert hd(cnames).domain == "admin.example.com"
      assert Authify.Configurations.get_global_setting(:email_link_domain) == "admin.example.com"

      # Now change authify_domain to a different domain
      conn
      |> recycle()
      |> log_in_user(admin)
      |> patch(~p"/#{global_org.slug}/settings/configuration", %{
        "authify_domain" => "portal.example.com"
      })

      # Verify old CNAME was deleted and new one created
      cnames = Authify.Organizations.list_organization_cnames(global_org)
      assert length(cnames) == 1
      assert hd(cnames).domain == "portal.example.com"
      assert Authify.Configurations.get_global_setting(:email_link_domain) == "portal.example.com"

      # Verify old domain is NOT in the list
      refute Enum.any?(cnames, &(&1.domain == "admin.example.com"))
    end

    test "clearing authify_domain removes all CNAMEs", %{conn: conn} do
      global_org = Authify.Accounts.get_global_organization()
      admin = user_fixture(%{organization: global_org, role: "admin"})

      # Set tenant base domain
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # First, set authify_domain to create CNAME
      conn
      |> log_in_user(admin)
      |> patch(~p"/#{global_org.slug}/settings/configuration", %{
        "authify_domain" => "admin.example.com"
      })

      # Verify CNAME was created
      cnames = Authify.Organizations.list_organization_cnames(global_org)
      assert length(cnames) == 1

      # Now clear authify_domain
      conn
      |> recycle()
      |> log_in_user(admin)
      |> patch(~p"/#{global_org.slug}/settings/configuration", %{
        "authify_domain" => ""
      })

      # Verify all CNAMEs were removed
      cnames = Authify.Organizations.list_organization_cnames(global_org)
      assert Enum.empty?(cnames)
      # email_link_domain should be nil or empty when cleared
      assert Authify.Configurations.get_global_setting(:email_link_domain) in [nil, ""]
    end

    test "tenant organization can set email_link_domain", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Set tenant base domain first
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Create a CNAME for the organization
      {:ok, _cname} =
        Authify.Organizations.create_cname(%{
          organization_id: organization.id,
          domain: "myapp.example.com"
        })

      # Set email_link_domain to the CNAME
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "settings" => %{
            "email_link_domain" => "myapp.example.com"
          }
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"

      # Verify email_link_domain was set
      assert Authify.Configurations.get_organization_setting(organization, :email_link_domain) ==
               "myapp.example.com"
    end

    test "tenant organization cannot set email_link_domain to invalid domain", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Set tenant base domain first
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Try to set email_link_domain to a domain that's not in allowed list
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "settings" => %{
            "email_link_domain" => "notallowed.example.com"
          }
        })

      # Should get an error
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "Error updating some settings"
    end

    test "tenant organization can manage custom domains via textarea", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Set tenant base domain first
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Add custom domains via textarea
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "custom_domains" => "myapp.example.com\napp.mycompany.com"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"

      # Verify CNAMEs were created
      cnames = Authify.Organizations.list_organization_cnames(organization)
      assert length(cnames) == 2
      domains = Enum.map(cnames, & &1.domain) |> Enum.sort()
      assert domains == ["app.mycompany.com", "myapp.example.com"]
    end

    test "tenant organization can update custom domains (add/remove)", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Set tenant base domain first
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Create initial CNAMEs
      {:ok, _} =
        Authify.Organizations.create_cname(%{
          organization_id: organization.id,
          domain: "old.example.com"
        })

      {:ok, _} =
        Authify.Organizations.create_cname(%{
          organization_id: organization.id,
          domain: "keep.example.com"
        })

      # Update domains - keep one, remove one, add one
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "custom_domains" => "keep.example.com\nnew.example.com"
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"

      # Verify CNAMEs were synced correctly
      cnames = Authify.Organizations.list_organization_cnames(organization)
      assert length(cnames) == 2
      domains = Enum.map(cnames, & &1.domain) |> Enum.sort()
      assert domains == ["keep.example.com", "new.example.com"]
    end

    test "tenant organization can clear all custom domains", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Set tenant base domain first
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Create initial CNAMEs
      {:ok, _} =
        Authify.Organizations.create_cname(%{
          organization_id: organization.id,
          domain: "app.example.com"
        })

      # Clear all domains with empty textarea
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "custom_domains" => ""
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"

      # Verify all CNAMEs were removed
      cnames = Authify.Organizations.list_organization_cnames(organization)
      assert Enum.empty?(cnames)
    end

    test "custom domains textarea handles whitespace and duplicates", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Set tenant base domain first
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Add domains with extra whitespace and duplicates
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "custom_domains" => "  myapp.example.com  \n\nmyapp.example.com\n  app.example.com  "
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"

      # Verify duplicates were removed and whitespace trimmed
      cnames = Authify.Organizations.list_organization_cnames(organization)
      assert length(cnames) == 2
      domains = Enum.map(cnames, & &1.domain) |> Enum.sort()
      assert domains == ["app.example.com", "myapp.example.com"]
    end

    test "invalid custom domain shows error", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Set tenant base domain first
      Authify.Configurations.set_global_setting(:tenant_base_domain, "authify.example.com")

      # Try to add invalid domain
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "custom_domains" => "invalid domain with spaces"
        })

      # Should get an error
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Custom domains"
    end

    test "tenant organization can configure SMTP settings", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Configure SMTP settings
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "settings" => %{
            "smtp_server" => "smtp.gmail.com",
            "smtp_port" => "587",
            "smtp_username" => "test@example.com",
            "smtp_password" => "secret123",
            "smtp_from_email" => "noreply@example.com",
            "smtp_from_name" => "Test Org",
            "smtp_use_ssl" => "true"
          }
        })

      assert redirected_to(conn) == ~p"/#{organization.slug}/settings/configuration"

      # Verify SMTP settings were saved
      assert Authify.Configurations.get_organization_setting(organization, :smtp_server) ==
               "smtp.gmail.com"

      assert Authify.Configurations.get_organization_setting(organization, :smtp_port) == 587

      assert Authify.Configurations.get_organization_setting(organization, :smtp_username) ==
               "test@example.com"

      assert Authify.Configurations.get_organization_setting(organization, :smtp_password) ==
               "secret123"

      assert Authify.Configurations.get_organization_setting(organization, :smtp_from_email) ==
               "noreply@example.com"

      assert Authify.Configurations.get_organization_setting(organization, :smtp_from_name) ==
               "Test Org"

      assert Authify.Configurations.get_organization_setting(organization, :smtp_use_ssl) == true
    end

    test "SMTP port validates correctly", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Try to set invalid port
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "settings" => %{
            "smtp_port" => "99999"
          }
        })

      # Should get an error
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "Error updating some settings"
    end

    test "SMTP from_email validates correctly", %{conn: conn} do
      organization = organization_fixture()
      admin = user_fixture(%{organization: organization, role: "admin"})

      # Try to set invalid email
      conn =
        conn
        |> log_in_user(admin)
        |> patch(~p"/#{organization.slug}/settings/configuration", %{
          "settings" => %{
            "smtp_from_email" => "not-an-email"
          }
        })

      # Should get an error
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~
               "Error updating some settings"
    end
  end
end
