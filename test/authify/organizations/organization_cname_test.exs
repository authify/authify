defmodule Authify.Organizations.OrganizationCnameTest do
  use Authify.DataCase, async: true

  alias Authify.Organizations.OrganizationCname

  import Authify.AccountsFixtures

  describe "changeset/2" do
    test "valid changeset with all required fields" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        domain: "sso.example.com"
      }

      changeset = OrganizationCname.changeset(%OrganizationCname{}, attrs)

      assert changeset.valid?
      assert get_change(changeset, :domain) == "sso.example.com"
      assert get_change(changeset, :organization_id) == org.id
      assert get_field(changeset, :verified) == false
    end

    test "requires organization_id" do
      attrs = %{domain: "sso.example.com"}

      changeset = OrganizationCname.changeset(%OrganizationCname{}, attrs)

      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).organization_id
    end

    test "requires domain" do
      org = organization_fixture()
      attrs = %{organization_id: org.id}

      changeset = OrganizationCname.changeset(%OrganizationCname{}, attrs)

      refute changeset.valid?
      assert "can't be blank" in errors_on(changeset).domain
    end

    test "validates domain format" do
      org = organization_fixture()

      invalid_domains = [
        "not a domain",
        "-starts-with-hyphen.com",
        "ends-with-hyphen-.com",
        "has_underscore.com",
        "has spaces.com",
        ".starts-with-dot.com",
        "ends-with-dot.com.",
        "has..double-dot.com"
      ]

      for domain <- invalid_domains do
        attrs = %{organization_id: org.id, domain: domain}
        changeset = OrganizationCname.changeset(%OrganizationCname{}, attrs)

        refute changeset.valid?,
               "Expected domain '#{domain}' to be invalid, but changeset was valid"

        assert "must be a valid domain name" in errors_on(changeset).domain
      end
    end

    test "accepts valid domain formats" do
      org = organization_fixture()

      valid_domains = [
        "example.com",
        "sso.example.com",
        "auth.acme.example.com",
        "my-domain.com",
        "123.example.com",
        "a.b.c.d.e.example.com",
        "UPPERCASE.COM"
      ]

      for domain <- valid_domains do
        attrs = %{organization_id: org.id, domain: domain}
        changeset = OrganizationCname.changeset(%OrganizationCname{}, attrs)

        assert changeset.valid?,
               "Expected domain '#{domain}' to be valid, but got errors: #{inspect(changeset.errors)}"
      end
    end

    test "normalizes domains to lowercase" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        domain: "SSO.EXAMPLE.COM"
      }

      changeset = OrganizationCname.changeset(%OrganizationCname{}, attrs)

      assert changeset.valid?
      assert get_change(changeset, :domain) == "sso.example.com"
    end

    test "prevents duplicate domains regardless of case" do
      org1 = organization_fixture()
      org2 = organization_fixture()

      # Create with lowercase
      {:ok, _} =
        %OrganizationCname{}
        |> OrganizationCname.changeset(%{
          organization_id: org1.id,
          domain: "sso.example.com"
        })
        |> Repo.insert()

      # Try to create with uppercase (should fail due to normalization)
      {:error, changeset} =
        %OrganizationCname{}
        |> OrganizationCname.changeset(%{
          organization_id: org2.id,
          domain: "SSO.EXAMPLE.COM"
        })
        |> Repo.insert()

      refute changeset.valid?

      assert "This domain is already in use by another organization" in errors_on(changeset).domain
    end

    test "validates domain length" do
      org = organization_fixture()

      # Domain longer than 253 characters
      long_domain = String.duplicate("a", 250) <> ".com"
      attrs = %{organization_id: org.id, domain: long_domain}

      changeset = OrganizationCname.changeset(%OrganizationCname{}, attrs)

      refute changeset.valid?
      assert "domain name too long" in errors_on(changeset).domain
    end

    test "enforces unique constraint on domain" do
      org1 = organization_fixture()
      org2 = organization_fixture()

      # Create first CNAME
      {:ok, _cname1} =
        %OrganizationCname{}
        |> OrganizationCname.changeset(%{
          organization_id: org1.id,
          domain: "sso.example.com"
        })
        |> Repo.insert()

      # Try to create duplicate CNAME for different org
      {:error, changeset} =
        %OrganizationCname{}
        |> OrganizationCname.changeset(%{
          organization_id: org2.id,
          domain: "sso.example.com"
        })
        |> Repo.insert()

      refute changeset.valid?

      assert "This domain is already in use by another organization" in errors_on(changeset).domain
    end
  end
end
