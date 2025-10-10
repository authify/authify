defmodule Authify.AuditLogTest do
  @moduledoc false
  use Authify.DataCase, async: true

  alias Authify.AuditLog
  alias Authify.AuditLog.Event

  import Authify.AccountsFixtures

  describe "log_event/2" do
    test "logs a successful login event" do
      org = organization_fixture()
      user = user_fixture(%{"organization_id" => org.id})

      attrs = %{
        organization_id: org.id,
        user_id: user.id,
        actor_type: "user",
        actor_name: "#{user.first_name} #{user.last_name}",
        outcome: "success",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0"
      }

      assert {:ok, %Event{} = event} = AuditLog.log_event(:login_success, attrs)
      assert event.event_type == "login_success"
      assert event.organization_id == org.id
      assert event.user_id == user.id
      assert event.actor_type == "user"
      assert event.outcome == "success"
      assert event.ip_address == "192.168.1.1"
    end

    test "logs a failed login event" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        actor_type: "user",
        actor_name: "unknown@example.com",
        outcome: "failure",
        ip_address: "192.168.1.1",
        metadata: %{reason: "invalid_credentials", attempted_email: "unknown@example.com"}
      }

      assert {:ok, %Event{} = event} = AuditLog.log_event(:login_failure, attrs)
      assert event.event_type == "login_failure"
      assert event.outcome == "failure"
      assert event.metadata.reason == "invalid_credentials"
    end

    test "logs an OAuth token grant event with API client" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        actor_type: "api_client",
        actor_name: "Mobile App",
        outcome: "success",
        resource_type: "OAuthClient",
        resource_id: 123,
        metadata: %{
          client_id: "abc123",
          scopes: ["read", "write"],
          grant_type: "authorization_code"
        }
      }

      assert {:ok, %Event{} = event} = AuditLog.log_event(:oauth_token_granted, attrs)
      assert event.event_type == "oauth_token_granted"
      assert event.actor_type == "api_client"
      assert event.actor_name == "Mobile App"
      assert event.metadata.scopes == ["read", "write"]
    end

    test "logs a SAML SSO event" do
      org = organization_fixture()
      user = user_fixture(%{"organization_id" => org.id})

      attrs = %{
        organization_id: org.id,
        user_id: user.id,
        actor_type: "user",
        outcome: "success",
        resource_type: "SAMLServiceProvider",
        resource_id: 456,
        metadata: %{
          sp_entity_id: "https://sp.example.com",
          nameid_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        }
      }

      assert {:ok, %Event{} = event} = AuditLog.log_event(:saml_assertion_issued, attrs)
      assert event.event_type == "saml_assertion_issued"
      assert event.metadata.sp_entity_id == "https://sp.example.com"
    end

    test "logs a permission denied event" do
      org = organization_fixture()
      user = user_fixture(%{"organization_id" => org.id})

      attrs = %{
        organization_id: org.id,
        user_id: user.id,
        actor_type: "user",
        outcome: "denied",
        resource_type: "Organization",
        resource_id: 999,
        metadata: %{attempted_action: "delete", reason: "insufficient_permissions"}
      }

      assert {:ok, %Event{} = event} = AuditLog.log_event(:permission_denied, attrs)
      assert event.outcome == "denied"
      assert event.metadata.attempted_action == "delete"
    end

    test "requires organization_id" do
      attrs = %{
        actor_type: "user",
        outcome: "success"
      }

      assert {:error, changeset} = AuditLog.log_event(:login_success, attrs)
      assert "can't be blank" in errors_on(changeset).organization_id
    end

    test "requires valid event_type" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "success"
      }

      assert {:error, changeset} = AuditLog.log_event(:invalid_event, attrs)
      assert "is invalid" in errors_on(changeset).event_type
    end

    test "requires valid actor_type" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        actor_type: "invalid",
        outcome: "success"
      }

      assert {:error, changeset} = AuditLog.log_event(:login_success, attrs)
      assert "is invalid" in errors_on(changeset).actor_type
    end

    test "requires valid outcome" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "invalid"
      }

      assert {:error, changeset} = AuditLog.log_event(:login_success, attrs)
      assert "is invalid" in errors_on(changeset).outcome
    end
  end

  describe "log_event_async/2" do
    test "logs event asynchronously" do
      org = organization_fixture()

      attrs = %{
        organization_id: org.id,
        actor_type: "system",
        outcome: "success"
      }

      assert :ok = AuditLog.log_event_async(:login_success, attrs)

      # Give async task time to complete
      Process.sleep(100)

      events = AuditLog.list_events(organization_id: org.id)
      assert length(events) == 1
      assert hd(events).event_type == "login_success"
    end
  end

  describe "list_events/1" do
    test "lists events for an organization" do
      org1 = organization_fixture()
      org2 = organization_fixture()

      AuditLog.log_event(:login_success, %{
        organization_id: org1.id,
        actor_type: "user",
        outcome: "success"
      })

      AuditLog.log_event(:login_success, %{
        organization_id: org2.id,
        actor_type: "user",
        outcome: "success"
      })

      events = AuditLog.list_events(organization_id: org1.id)
      assert length(events) == 1
      assert hd(events).organization_id == org1.id
    end

    test "filters by event_type" do
      org = organization_fixture()

      AuditLog.log_event(:login_success, %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "success"
      })

      AuditLog.log_event(:logout, %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "success"
      })

      events = AuditLog.list_events(organization_id: org.id, event_type: "login_success")
      assert length(events) == 1
      assert hd(events).event_type == "login_success"
    end

    test "filters by actor_type" do
      org = organization_fixture()

      AuditLog.log_event(:login_success, %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "success"
      })

      AuditLog.log_event(:api_access, %{
        organization_id: org.id,
        actor_type: "api_client",
        outcome: "success"
      })

      events = AuditLog.list_events(organization_id: org.id, actor_type: "api_client")
      assert length(events) == 1
      assert hd(events).actor_type == "api_client"
    end

    test "filters by outcome" do
      org = organization_fixture()

      AuditLog.log_event(:login_success, %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "success"
      })

      AuditLog.log_event(:login_failure, %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "failure"
      })

      events = AuditLog.list_events(organization_id: org.id, outcome: "failure")
      assert length(events) == 1
      assert hd(events).outcome == "failure"
    end

    test "filters by date range" do
      org = organization_fixture()

      {:ok, old_event} =
        AuditLog.log_event(:login_success, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "success"
        })

      # Backdate the event
      from(e in Event, where: e.id == ^old_event.id)
      |> Repo.update_all(set: [inserted_at: ~U[2025-01-01 00:00:00Z]])

      AuditLog.log_event(:login_success, %{
        organization_id: org.id,
        actor_type: "user",
        outcome: "success"
      })

      events = AuditLog.list_events(organization_id: org.id, from_date: ~U[2025-10-01 00:00:00Z])
      assert length(events) == 1
    end

    test "respects limit and offset" do
      org = organization_fixture()

      Enum.each(1..10, fn _ ->
        AuditLog.log_event(:login_success, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "success"
        })
      end)

      events = AuditLog.list_events(organization_id: org.id, limit: 5)
      assert length(events) == 5

      events = AuditLog.list_events(organization_id: org.id, limit: 5, offset: 5)
      assert length(events) == 5
    end
  end

  describe "count_events/1" do
    test "counts events for an organization" do
      org = organization_fixture()

      Enum.each(1..5, fn _ ->
        AuditLog.log_event(:login_success, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "success"
        })
      end)

      assert AuditLog.count_events(organization_id: org.id) == 5
    end

    test "counts events with filters" do
      org = organization_fixture()

      Enum.each(1..3, fn _ ->
        AuditLog.log_event(:login_success, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "success"
        })
      end)

      Enum.each(1..2, fn _ ->
        AuditLog.log_event(:login_failure, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "failure"
        })
      end)

      assert AuditLog.count_events(organization_id: org.id, event_type: "login_success") == 3
      assert AuditLog.count_events(organization_id: org.id, outcome: "failure") == 2
    end
  end

  describe "get_event/2" do
    test "gets an event by ID" do
      org = organization_fixture()

      {:ok, event} =
        AuditLog.log_event(:login_success, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "success"
        })

      assert {:ok, fetched_event} = AuditLog.get_event(event.id, organization_id: org.id)
      assert fetched_event.id == event.id
    end

    test "returns error for non-existent event" do
      org = organization_fixture()
      assert {:error, :not_found} = AuditLog.get_event(999_999, organization_id: org.id)
    end

    test "returns error when event belongs to different organization" do
      org1 = organization_fixture()
      org2 = organization_fixture()

      {:ok, event} =
        AuditLog.log_event(:login_success, %{
          organization_id: org1.id,
          actor_type: "user",
          outcome: "success"
        })

      assert {:error, :not_found} = AuditLog.get_event(event.id, organization_id: org2.id)
    end
  end

  describe "get_event_stats/1" do
    test "returns statistics for events" do
      org = organization_fixture()

      Enum.each(1..5, fn _ ->
        AuditLog.log_event(:login_success, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "success"
        })
      end)

      Enum.each(1..3, fn _ ->
        AuditLog.log_event(:login_failure, %{
          organization_id: org.id,
          actor_type: "user",
          outcome: "failure"
        })
      end)

      Enum.each(1..2, fn _ ->
        AuditLog.log_event(:api_access, %{
          organization_id: org.id,
          actor_type: "api_client",
          outcome: "success"
        })
      end)

      stats = AuditLog.get_event_stats(organization_id: org.id)

      assert stats.total == 10
      assert stats.by_event_type["login_success"] == 5
      assert stats.by_event_type["login_failure"] == 3
      assert stats.by_event_type["api_access"] == 2
      assert stats.by_outcome["success"] == 7
      assert stats.by_outcome["failure"] == 3
      assert stats.by_actor_type["user"] == 8
      assert stats.by_actor_type["api_client"] == 2
    end
  end
end
