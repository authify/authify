defmodule Authify.SAMLTest do
  use Authify.DataCase

  alias Authify.SAML
  alias Authify.SAML.{Certificate, ServiceProvider, Session}

  import Authify.AccountsFixtures
  import Authify.SAMLFixtures

  describe "service_providers" do
    @valid_attrs %{
      name: "Test SP",
      entity_id: "https://test-sp.example.com",
      acs_url: "https://test-sp.example.com/saml/acs",
      sls_url: "https://test-sp.example.com/saml/sls",
      certificate:
        "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890\n-----END CERTIFICATE-----",
      metadata: "<?xml>metadata</xml>",
      attribute_mapping: "{\"email\": \"email\"}",
      sign_requests: false,
      sign_assertions: true,
      encrypt_assertions: false,
      is_active: true
    }

    @invalid_attrs %{
      name: nil,
      entity_id: nil,
      acs_url: nil,
      organization_id: nil
    }

    test "list_service_providers/1 returns all service providers for an organization" do
      organization = organization_fixture()
      sp = service_provider_fixture(organization: organization)
      service_providers = SAML.list_service_providers(organization)

      assert length(service_providers) == 1
      assert hd(service_providers).id == sp.id
    end

    test "get_service_provider!/2 returns the service provider with given id and organization" do
      organization = organization_fixture()
      sp = service_provider_fixture(organization: organization)
      found_sp = SAML.get_service_provider!(sp.id, organization)

      assert found_sp.id == sp.id
      assert found_sp.name == sp.name
      assert found_sp.organization_id == organization.id
    end

    test "get_service_provider_by_entity_id/1 returns active service provider by entity ID" do
      sp =
        service_provider_fixture(%{entity_id: "https://unique-sp.example.com", is_active: true})

      found_sp = SAML.get_service_provider_by_entity_id("https://unique-sp.example.com")

      assert found_sp.id == sp.id
      assert found_sp.entity_id == sp.entity_id
    end

    test "get_service_provider_by_entity_id/1 returns nil for inactive service provider" do
      service_provider_fixture(%{entity_id: "https://inactive-sp.example.com", is_active: false})
      found_sp = SAML.get_service_provider_by_entity_id("https://inactive-sp.example.com")

      assert found_sp == nil
    end

    test "create_service_provider/1 with valid data creates a service provider" do
      organization = organization_fixture()
      attrs = Map.put(@valid_attrs, :organization_id, organization.id)

      assert {:ok, %ServiceProvider{} = sp} = SAML.create_service_provider(attrs)
      assert sp.name == "Test SP"
      assert sp.entity_id == "https://test-sp.example.com"
      assert sp.acs_url == "https://test-sp.example.com/saml/acs"
      assert sp.sls_url == "https://test-sp.example.com/saml/sls"
      assert sp.is_active == true
    end

    test "create_service_provider/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = SAML.create_service_provider(@invalid_attrs)
    end

    test "update_service_provider/2 with valid data updates the service provider" do
      sp = service_provider_fixture()
      update_attrs = %{name: "Updated SP", entity_id: "https://updated-sp.example.com"}

      assert {:ok, %ServiceProvider{} = updated_sp} =
               SAML.update_service_provider(sp, update_attrs)

      assert updated_sp.name == "Updated SP"
      assert updated_sp.entity_id == "https://updated-sp.example.com"
    end

    test "delete_service_provider/1 deletes the service provider" do
      sp = service_provider_fixture()
      assert {:ok, %ServiceProvider{}} = SAML.delete_service_provider(sp)

      assert_raise Ecto.NoResultsError, fn ->
        SAML.get_service_provider!(sp.id, sp.organization)
      end
    end

    test "change_service_provider/1 returns a service provider changeset" do
      sp = service_provider_fixture()
      assert %Ecto.Changeset{} = SAML.change_service_provider(sp)
    end
  end

  describe "sessions" do
    test "create_session/1 with valid data creates a SAML session" do
      sp = service_provider_fixture()
      user = user_for_organization_fixture(sp.organization)
      session_id = Session.generate_session_id()
      subject_id = Session.generate_subject_id(user, sp)

      attrs = %{
        session_id: session_id,
        subject_id: subject_id,
        request_id: "test_request_123",
        relay_state: "test_relay",
        issued_at: DateTime.utc_now() |> DateTime.truncate(:second),
        expires_at:
          DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second),
        user_id: user.id,
        service_provider_id: sp.id
      }

      assert {:ok, %Session{} = session} = SAML.create_session(attrs)
      assert session.session_id == session_id
      assert session.subject_id == subject_id
      assert session.request_id == "test_request_123"
      assert session.user_id == user.id
      assert session.service_provider_id == sp.id
    end

    test "get_session/1 returns session by session ID" do
      session = saml_session_fixture()
      found_session = SAML.get_session(session.session_id)

      assert found_session.id == session.id
      assert found_session.session_id == session.session_id
      assert found_session.user.id == session.user_id
      assert found_session.service_provider.id == session.service_provider_id
    end

    test "get_session/1 returns nil for non-existent session" do
      assert SAML.get_session("non_existent_session") == nil
    end

    test "get_active_sessions_for_user/1 returns active sessions only" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp1 = service_provider_fixture(organization: organization)

      sp2 =
        service_provider_fixture(%{
          organization: organization,
          entity_id: "https://sp2.example.com"
        })

      # Create active session
      active_session = saml_session_fixture(%{user: user, service_provider: sp1})

      # Create expired session
      expired_time =
        DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second)

      saml_session_fixture(%{
        user: user,
        service_provider: sp2,
        expires_at: expired_time
      })

      active_sessions = SAML.get_active_sessions_for_user(user)
      assert length(active_sessions) == 1
      assert hd(active_sessions).id == active_session.id
    end

    test "terminate_session/1 expires a session immediately" do
      session = saml_session_fixture()
      assert DateTime.compare(session.expires_at, DateTime.utc_now()) == :gt

      assert {:ok, terminated_session} = SAML.terminate_session(session)
      assert DateTime.compare(terminated_session.expires_at, DateTime.utc_now()) in [:lt, :eq]
    end

    test "terminate_all_sessions_for_user/1 expires all user sessions" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp1 = service_provider_fixture(organization: organization)

      sp2 =
        service_provider_fixture(%{
          organization: organization,
          entity_id: "https://sp2.example.com"
        })

      session1 = saml_session_fixture(%{user: user, service_provider: sp1})
      session2 = saml_session_fixture(%{user: user, service_provider: sp2})

      # Both sessions should be active initially
      assert DateTime.compare(session1.expires_at, DateTime.utc_now()) == :gt
      assert DateTime.compare(session2.expires_at, DateTime.utc_now()) == :gt

      {updated_count, _} = SAML.terminate_all_sessions_for_user(user)
      assert updated_count == 2

      # Check sessions are now expired
      active_sessions = SAML.get_active_sessions_for_user(user)
      assert Enum.empty?(active_sessions)
    end
  end

  describe "session utilities" do
    test "Session.generate_session_id/0 generates unique session IDs" do
      id1 = Session.generate_session_id()
      id2 = Session.generate_session_id()

      assert is_binary(id1)
      assert is_binary(id2)
      assert id1 != id2
      assert String.length(id1) > 30
    end

    test "Session.generate_subject_id/2 generates consistent subject IDs" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp = service_provider_fixture(organization: organization)

      subject_id1 = Session.generate_subject_id(user, sp)
      subject_id2 = Session.generate_subject_id(user, sp)

      # Same user + SP should generate same subject ID
      assert subject_id1 == subject_id2
      assert is_binary(subject_id1)
    end

    test "Session.expired?/1 correctly identifies expired sessions" do
      expired_session = %Session{expires_at: DateTime.add(DateTime.utc_now(), -1, :hour)}
      active_session = %Session{expires_at: DateTime.add(DateTime.utc_now(), 1, :hour)}

      assert Session.expired?(expired_session) == true
      assert Session.expired?(active_session) == false
    end

    test "Session.valid?/1 correctly identifies valid sessions" do
      expired_session = %Session{expires_at: DateTime.add(DateTime.utc_now(), -1, :hour)}
      active_session = %Session{expires_at: DateTime.add(DateTime.utc_now(), 1, :hour)}

      assert Session.valid?(expired_session) == false
      assert Session.valid?(active_session) == true
    end
  end

  describe "certificates" do
    test "list_certificates/1 returns all certificates for an organization" do
      organization = organization_fixture()
      cert = certificate_fixture(organization: organization)
      certificates = SAML.list_certificates(organization)

      assert length(certificates) == 1
      assert hd(certificates).id == cert.id
    end

    test "get_active_certificate/2 returns active certificate for purpose" do
      organization = organization_fixture()
      # Create active signing certificate
      signing_cert =
        certificate_fixture(%{
          organization: organization,
          purpose: "signing",
          is_active: true,
          expires_at:
            DateTime.utc_now()
            |> DateTime.add(365 * 24 * 3600, :second)
            |> DateTime.truncate(:second)
        })

      # Create inactive signing certificate
      certificate_fixture(%{
        organization: organization,
        purpose: "signing",
        is_active: false
      })

      found_cert = SAML.get_active_certificate(organization, "signing")
      assert found_cert.id == signing_cert.id
    end

    test "get_active_certificate/2 returns nil for expired certificate" do
      organization = organization_fixture()

      certificate_fixture(%{
        organization: organization,
        purpose: "signing",
        is_active: true,
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :day) |> DateTime.truncate(:second)
      })

      found_cert = SAML.get_active_certificate(organization, "signing")
      assert found_cert == nil
    end

    test "create_certificate/1 with valid data creates a certificate" do
      organization = organization_fixture()

      attrs = %{
        name: "Test Cert",
        certificate:
          "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890\n-----END CERTIFICATE-----",
        private_key: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        purpose: "signing",
        expires_at:
          DateTime.utc_now()
          |> DateTime.add(365 * 24 * 3600, :second)
          |> DateTime.truncate(:second),
        is_active: true,
        organization_id: organization.id
      }

      assert {:ok, %Certificate{} = cert} = SAML.create_certificate(attrs)
      assert cert.name == "Test Cert"
      assert cert.purpose == "signing"
      assert cert.is_active == true
    end
  end

  describe "SAML request parsing" do
    test "parse_saml_request/1 with valid XML returns parsed data" do
      saml_request = sample_saml_request()
      assert {:ok, request_info} = SAML.parse_saml_request(saml_request)

      assert is_binary(request_info.request_id)
      assert is_binary(request_info.issuer)
      assert is_binary(request_info.acs_url)
    end

    @tag :capture_log
    test "parse_saml_request/1 with empty XML returns error" do
      assert {:error, "Data is neither valid Base64 nor XML"} = SAML.parse_saml_request("")
      assert {:error, "SAML request cannot be empty"} = SAML.parse_saml_request(nil)
    end

    test "parse_saml_logout_request/1 with valid XML returns parsed data" do
      logout_request = sample_saml_logout_request()
      assert {:ok, logout_info} = SAML.parse_saml_logout_request(logout_request)

      assert is_binary(logout_info.request_id)
      assert is_binary(logout_info.issuer)
      assert is_binary(logout_info.session_index)
      assert is_binary(logout_info.name_id)
    end

    @tag :capture_log
    test "parse_saml_logout_request/1 with empty XML returns error" do
      assert {:error, "Data is neither valid Base64 nor XML"} = SAML.parse_saml_logout_request("")
      assert {:error, "SAML logout request cannot be empty"} = SAML.parse_saml_logout_request(nil)
    end
  end

  describe "SAML response generation" do
    test "generate_saml_response/3 creates valid SAML response" do
      session = saml_session_fixture()
      sp = session.service_provider
      user = session.user

      assert {:ok, saml_response} = SAML.generate_saml_response(session, sp, user)
      assert is_binary(saml_response)
      assert String.contains?(saml_response, "saml2p:Response")
      assert String.contains?(saml_response, session.request_id)
      assert String.contains?(saml_response, sp.acs_url)
      assert String.contains?(saml_response, session.subject_id)
    end

    test "generate_saml_logout_response/2 creates valid logout response" do
      sp = service_provider_fixture()

      logout_request = %{
        request_id: "test_logout_request_123",
        issuer: sp.entity_id
      }

      assert {:ok, logout_response} = SAML.generate_saml_logout_response(logout_request, sp)
      assert is_binary(logout_response)
      assert String.contains?(logout_response, "saml2p:LogoutResponse")
      assert String.contains?(logout_response, logout_request.request_id)
      assert String.contains?(logout_response, "Success")
    end

    test "generate_saml_logout_request/2 creates valid logout request" do
      session = saml_session_fixture()
      sp = session.service_provider

      assert {:ok, logout_request, request_id} = SAML.generate_saml_logout_request(session, sp)
      assert is_binary(logout_request)
      assert is_binary(request_id)
      assert String.contains?(logout_request, "saml2p:LogoutRequest")
      assert String.contains?(logout_request, session.subject_id)
      assert String.contains?(logout_request, session.session_id)
    end
  end

  describe "session cleanup" do
    test "cleanup_expired_sessions/0 removes only expired sessions" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      sp = service_provider_fixture(organization: organization)

      # Create active session
      saml_session_fixture(%{user: user, service_provider: sp})

      # Create expired session
      expired_time =
        DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second)

      saml_session_fixture(%{
        user: user,
        service_provider: sp,
        expires_at: expired_time
      })

      # Should have 2 sessions total, 1 expired
      all_sessions = Authify.Repo.all(Session)
      assert length(all_sessions) == 2

      # Cleanup expired sessions
      assert {:ok, %{saml_sessions: {deleted_count, _}}} = SAML.cleanup_expired_sessions()
      assert deleted_count == 1

      # Should have 1 session remaining
      remaining_sessions = Authify.Repo.all(Session)
      assert length(remaining_sessions) == 1
    end
  end

  describe "attribute mapping with mustache interpolation" do
    test "interpolates simple field placeholders" do
      organization = organization_fixture()

      user =
        user_for_organization_fixture(organization, %{
          "email" => "test@example.com",
          "first_name" => "John",
          "last_name" => "Doe",
          "username" => "johndoe"
        })

      sp =
        service_provider_fixture(%{
          organization: organization,
          attribute_mapping:
            Jason.encode!(%{
              "email" => "{{email}}",
              "username" => "{{username}}",
              "firstName" => "{{first_name}}",
              "lastName" => "{{last_name}}"
            })
        })

      session = saml_session_fixture(%{user: user, service_provider: sp})
      assert {:ok, response} = SAML.generate_saml_response(session, sp, user)

      assert String.contains?(response, ~s(<saml2:Attribute Name="email">))

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>test@example.com</saml2:AttributeValue>)
             )

      assert String.contains?(response, ~s(<saml2:Attribute Name="firstName">))
      assert String.contains?(response, ~s(<saml2:AttributeValue>John</saml2:AttributeValue>))
      assert String.contains?(response, ~s(<saml2:Attribute Name="lastName">))
      assert String.contains?(response, ~s(<saml2:AttributeValue>Doe</saml2:AttributeValue>))
      assert String.contains?(response, ~s(<saml2:Attribute Name="username">))
      assert String.contains?(response, ~s(<saml2:AttributeValue>johndoe</saml2:AttributeValue>))
    end

    test "interpolates multiple fields in a single template" do
      organization = organization_fixture()

      user =
        user_for_organization_fixture(organization, %{
          "email" => "jane@example.com",
          "first_name" => "Jane",
          "last_name" => "Smith"
        })

      sp =
        service_provider_fixture(%{
          organization: organization,
          attribute_mapping:
            Jason.encode!(%{
              "displayName" => "{{first_name}} {{last_name}}",
              "fullName" => "{{last_name}}, {{first_name}}",
              "emailWithName" => "{{first_name}} {{last_name}} <{{email}}>"
            })
        })

      session = saml_session_fixture(%{user: user, service_provider: sp})
      assert {:ok, response} = SAML.generate_saml_response(session, sp, user)

      assert String.contains?(response, ~s(<saml2:Attribute Name="displayName">))

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>Jane Smith</saml2:AttributeValue>)
             )

      assert String.contains?(response, ~s(<saml2:Attribute Name="fullName">))

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>Smith, Jane</saml2:AttributeValue>)
             )

      assert String.contains?(response, ~s(<saml2:Attribute Name="emailWithName">))

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>Jane Smith &lt;jane@example.com&gt;</saml2:AttributeValue>)
             )
    end

    test "handles whitespace in template placeholders" do
      organization = organization_fixture()

      user =
        user_for_organization_fixture(organization, %{
          "first_name" => "Bob",
          "last_name" => "Johnson"
        })

      sp =
        service_provider_fixture(%{
          organization: organization,
          attribute_mapping:
            Jason.encode!(%{
              "name" => "{{ first_name }} {{ last_name }}"
            })
        })

      session = saml_session_fixture(%{user: user, service_provider: sp})
      assert {:ok, response} = SAML.generate_saml_response(session, sp, user)

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>Bob Johnson</saml2:AttributeValue>)
             )
    end

    test "handles missing field values gracefully" do
      organization = organization_fixture()

      user =
        user_for_organization_fixture(organization, %{
          "first_name" => "Alice",
          "last_name" => nil
        })

      sp =
        service_provider_fixture(%{
          organization: organization,
          attribute_mapping:
            Jason.encode!(%{
              "displayName" => "{{first_name}} {{last_name}}"
            })
        })

      session = saml_session_fixture(%{user: user, service_provider: sp})
      assert {:ok, response} = SAML.generate_saml_response(session, sp, user)

      # Should contain "Alice" but handle nil last_name gracefully
      assert String.contains?(response, ~s(<saml2:AttributeValue>Alice</saml2:AttributeValue>))
    end

    test "handles multi-valued attributes like groups" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      # Create groups and assign to user
      {:ok, group1} =
        Authify.Accounts.create_group(%{
          name: "Developers",
          organization_id: organization.id
        })

      {:ok, group2} =
        Authify.Accounts.create_group(%{
          name: "Admins",
          organization_id: organization.id
        })

      Authify.Accounts.add_user_to_group(user, group1)
      Authify.Accounts.add_user_to_group(user, group2)

      sp =
        service_provider_fixture(%{
          organization: organization,
          attribute_mapping:
            Jason.encode!(%{
              "groups" => "{{groups}}"
            })
        })

      # Reload user with groups preloaded
      user = Authify.Repo.preload(user, :groups, force: true)
      session = saml_session_fixture(%{user: user, service_provider: sp})
      assert {:ok, response} = SAML.generate_saml_response(session, sp, user)

      assert String.contains?(response, ~s(<saml2:Attribute Name="groups">))

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>Developers</saml2:AttributeValue>)
             )

      assert String.contains?(response, ~s(<saml2:AttributeValue>Admins</saml2:AttributeValue>))
    end

    test "uses default attribute mapping when none specified" do
      organization = organization_fixture()

      user =
        user_for_organization_fixture(organization, %{
          "email" => "default@example.com",
          "first_name" => "Default",
          "last_name" => "User",
          "username" => "defaultuser"
        })

      sp =
        service_provider_fixture(%{
          organization: organization,
          attribute_mapping: nil
        })

      session = saml_session_fixture(%{user: user, service_provider: sp})
      assert {:ok, response} = SAML.generate_saml_response(session, sp, user)

      # Should use default mapping
      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>default@example.com</saml2:AttributeValue>)
             )

      assert String.contains?(response, ~s(<saml2:AttributeValue>Default</saml2:AttributeValue>))
      assert String.contains?(response, ~s(<saml2:AttributeValue>User</saml2:AttributeValue>))

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>Default User</saml2:AttributeValue>)
             )

      assert String.contains?(
               response,
               ~s(<saml2:AttributeValue>defaultuser</saml2:AttributeValue>)
             )
    end

    test "properly escapes HTML special characters in attribute values" do
      organization = organization_fixture()

      user =
        user_for_organization_fixture(organization, %{
          "email" => "test@example.com",
          "first_name" => "John<script>",
          "last_name" => "Doe&Co"
        })

      sp =
        service_provider_fixture(%{
          organization: organization,
          attribute_mapping:
            Jason.encode!(%{
              "displayName" => "{{first_name}} {{last_name}}"
            })
        })

      session = saml_session_fixture(%{user: user, service_provider: sp})
      assert {:ok, response} = SAML.generate_saml_response(session, sp, user)

      # Should escape HTML entities
      assert String.contains?(response, "John&lt;script&gt; Doe&amp;Co")
      refute String.contains?(response, "<script>")
      refute String.contains?(response, "&Co")
    end
  end
end
