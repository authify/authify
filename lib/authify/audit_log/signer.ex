defmodule Authify.AuditLog.Signer do
  @moduledoc """
  Signs and verifies audit log events using RSA-SHA256.

  The canonical payload is a JSON object with a fixed set of fields in
  alphabetical key order, with nil values encoded as JSON null (never omitted).
  This determinism ensures the payload can be reconstructed independently for
  offline verification.
  """

  alias Authify.Accounts
  alias Authify.AuditLog.Event
  alias Authify.AuditLog.KeyCache

  @doc """
  Returns a deterministic JSON binary for the signable fields of an event.

  Keys are in alphabetical order; nil values are included as JSON null.
  """
  def canonical_payload(%Event{} = event) do
    # Pairs listed in alphabetical key order — order is intentional
    pairs = [
      {"actor_id", event.actor_id},
      {"actor_name", event.actor_name},
      {"actor_type", event.actor_type},
      {"event_type", event.event_type},
      {"inserted_at", DateTime.to_iso8601(event.inserted_at)},
      {"ip_address", event.ip_address},
      {"metadata", event.metadata},
      {"organization_id", event.organization_id},
      {"outcome", event.outcome},
      {"resource_id", event.resource_id},
      {"resource_type", event.resource_type},
      {"user_agent", event.user_agent}
    ]

    inner =
      Enum.map_join(pairs, ",", fn {k, v} ->
        Jason.encode!(k) <> ":" <> Jason.encode!(v)
      end)

    "{#{inner}}"
  end

  @doc """
  Signs an event for the given org_id using the org's active audit signing cert.

  Returns `{:ok, base64_signature, cert_id}` or `{:error, reason}`.
  Caches the decoded private key in `KeyCache` to avoid repeat DB lookups.
  """
  def sign(%Event{} = event, org_id) when is_integer(org_id) do
    with {:ok, private_key, cert_id} <- fetch_or_cache_key(org_id) do
      payload = canonical_payload(event)
      signature_bytes = :public_key.sign(payload, :sha256, private_key)
      {:ok, Base.encode64(signature_bytes), cert_id}
    end
  end

  @doc """
  Verifies a signed event against the PEM of the certificate that signed it.

  Returns `:ok`, `{:error, :invalid}`, or `{:error, :unsigned}`.
  """
  def verify(%Event{signature: nil}, _cert_pem), do: {:error, :unsigned}

  def verify(%Event{} = event, cert_pem) when is_binary(cert_pem) do
    with {:ok, cert} <- decode_certificate(cert_pem),
         public_key <- X509.Certificate.public_key(cert),
         {:ok, sig_bytes} <- Base.decode64(event.signature) do
      payload = canonical_payload(event)

      if :public_key.verify(payload, :sha256, sig_bytes, public_key) do
        :ok
      else
        {:error, :invalid}
      end
    else
      :error -> {:error, :invalid}
      {:error, _} -> {:error, :invalid}
    end
  end

  defp fetch_or_cache_key(org_id) do
    case KeyCache.get(org_id) do
      {:ok, %{private_key: private_key, cert_id: cert_id}} ->
        {:ok, private_key, cert_id}

      :miss ->
        with {:ok, cert} <- Accounts.get_or_generate_audit_signing_certificate(org_id),
             {:ok, pem} <- Accounts.decrypt_certificate_private_key(cert),
             {:ok, private_key} <- decode_private_key(pem) do
          KeyCache.put(org_id, private_key, cert.id)
          {:ok, private_key, cert.id}
        end
    end
  end

  defp decode_private_key(pem) do
    {:ok, X509.PrivateKey.from_pem!(pem)}
  rescue
    e -> {:error, e}
  end

  defp decode_certificate(pem) do
    {:ok, X509.Certificate.from_pem!(pem)}
  rescue
    e -> {:error, e}
  end
end
