defmodule Authify.SAML.GroupAttributesTest do
  use Authify.DataCase, async: true

  alias Authify.Accounts
  alias Authify.SAML

  describe "SAML group attributes" do
    setup do
      # Create organization
      {:ok, org} =
        Accounts.create_organization(%{
          name: "Test Organization",
          slug: "test-org",
          active: true
        })

      # Create user with username
      {:ok, user} =
        Accounts.create_user(%{
          "emails" => [%{"value" => "user@example.com", "type" => "work", "primary" => true}],
          "password" => "SecurePassword123!",
          "first_name" => "John",
          "last_name" => "Doe",
          "username" => "johndoe",
          "organization_id" => org.id,
          "role" => "user"
        })

      # Create groups
      {:ok, group1} =
        Accounts.create_group(%{
          name: "Engineering",
          description: "Engineering team",
          organization_id: org.id
        })

      {:ok, group2} =
        Accounts.create_group(%{
          name: "Admins",
          description: "Administrators",
          organization_id: org.id
        })

      # Add user to groups
      Accounts.add_user_to_group(user, group1)
      Accounts.add_user_to_group(user, group2)

      # Create service provider with attribute mapping
      {:ok, sp} =
        SAML.create_service_provider(%{
          name: "Test SP",
          entity_id: "https://sp.example.com",
          acs_url: "https://sp.example.com/saml/acs",
          organization_id: org.id,
          attribute_mapping:
            Jason.encode!(%{
              "username" => "{{username}}",
              "email" => "{{email}}",
              "displayName" => "{{first_name}} {{last_name}}",
              "memberOf" => "{{groups}}"
            })
        })

      # Create SAML session
      {:ok, session} =
        SAML.create_session(%{
          session_id: "test-session-id",
          request_id: "test-request-id",
          user_id: user.id,
          service_provider_id: sp.id,
          subject_id: "test-subject",
          issued_at: DateTime.utc_now() |> DateTime.truncate(:second),
          expires_at:
            DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)
        })

      %{user: user, org: org, sp: sp, session: session}
    end

    test "includes username in SAML assertion", %{user: user, sp: sp, session: session} do
      # Preload groups
      user = Repo.preload(user, :groups)

      {:ok, saml_response} = SAML.XML.generate_saml_response(session, sp, user)

      assert saml_response =~ ~s(<saml2:Attribute Name="username">)
      assert saml_response =~ ~s(<saml2:AttributeValue>johndoe</saml2:AttributeValue>)
    end

    test "includes groups as multi-valued attribute in SAML assertion", %{
      user: user,
      sp: sp,
      session: session
    } do
      # Preload groups
      user = Repo.preload(user, :groups)

      {:ok, saml_response} = SAML.XML.generate_saml_response(session, sp, user)

      assert saml_response =~ ~s(<saml2:Attribute Name="memberOf">)
      assert saml_response =~ ~s(<saml2:AttributeValue>Engineering</saml2:AttributeValue>)
      assert saml_response =~ ~s(<saml2:AttributeValue>Admins</saml2:AttributeValue>)
    end

    test "includes all mapped attributes in SAML assertion", %{
      user: user,
      sp: sp,
      session: session
    } do
      # Preload groups
      user = Repo.preload(user, :groups)

      {:ok, saml_response} = SAML.XML.generate_saml_response(session, sp, user)

      # Username
      assert saml_response =~ ~s(Name="username")
      assert saml_response =~ ~s(>johndoe<)

      # Email
      assert saml_response =~ ~s(Name="email")
      assert saml_response =~ ~s(>user@example.com<)

      # Display name
      assert saml_response =~ ~s(Name="displayName")
      assert saml_response =~ ~s(>John Doe<)

      # Groups
      assert saml_response =~ ~s(Name="memberOf")
      assert saml_response =~ ~s(>Engineering<)
      assert saml_response =~ ~s(>Admins<)
    end
  end
end
