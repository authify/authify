defmodule Authify.AuditLog.SignerTest do
  @moduledoc false
  use Authify.DataCase, async: true

  alias Authify.AuditLog.Event
  alias Authify.AuditLog.Signer

  import Authify.AccountsFixtures

  defp build_event(org_id) do
    %Event{
      id: 1,
      event_type: "login_success",
      actor_type: "user",
      actor_id: 42,
      actor_name: "Jane Doe",
      resource_type: nil,
      resource_id: nil,
      ip_address: "127.0.0.1",
      user_agent: "TestAgent/1.0",
      outcome: "success",
      metadata: %{"foo" => "bar"},
      organization_id: org_id,
      inserted_at: ~U[2026-05-20 12:00:00Z]
    }
  end

  describe "canonical_payload/1" do
    test "produces same output regardless of struct field order" do
      org = organization_fixture()
      event = build_event(org.id)

      payload1 = Signer.canonical_payload(event)
      payload2 = Signer.canonical_payload(event)

      assert payload1 == payload2
    end

    test "includes null for nil fields" do
      org = organization_fixture()
      event = build_event(org.id)

      payload = Signer.canonical_payload(event)
      decoded = Jason.decode!(payload)

      assert Map.has_key?(decoded, "resource_type")
      assert decoded["resource_type"] == nil
    end

    test "keys are in alphabetical order" do
      org = organization_fixture()
      event = build_event(org.id)

      payload = Signer.canonical_payload(event)
      decoded = Jason.decode!(payload)
      keys = Map.keys(decoded)

      assert keys == Enum.sort(keys)
    end
  end

  describe "sign/2 and verify/2" do
    setup do
      org = organization_fixture()
      {:ok, cert} = Authify.Accounts.get_or_generate_audit_signing_certificate(org.id)
      %{org: org, cert: cert}
    end

    test "sign/2 returns base64 signature and cert_id", %{org: org, cert: cert} do
      event = build_event(org.id)

      {:ok, signature, cert_id} = Signer.sign(event, org.id)

      assert is_binary(signature)
      assert Base.decode64(signature) != :error
      assert cert_id == cert.id
    end

    test "verify/2 returns :ok for a properly signed event", %{org: org, cert: cert} do
      event = build_event(org.id)
      {:ok, signature, _cert_id} = Signer.sign(event, org.id)

      signed_event = %{event | signature: signature}

      assert :ok == Signer.verify(signed_event, cert.certificate)
    end

    test "verify/2 returns {:error, :invalid} when payload is tampered", %{org: org, cert: cert} do
      event = build_event(org.id)
      {:ok, signature, _} = Signer.sign(event, org.id)

      tampered = %{event | signature: signature, actor_name: "Hacker"}

      assert {:error, :invalid} == Signer.verify(tampered, cert.certificate)
    end

    test "verify/2 returns {:error, :unsigned} for event with nil signature", %{cert: cert} do
      org = organization_fixture()
      event = build_event(org.id)

      assert {:error, :unsigned} == Signer.verify(event, cert.certificate)
    end
  end
end
