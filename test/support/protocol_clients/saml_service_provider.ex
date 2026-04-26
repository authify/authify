defmodule AuthifyTest.SAMLServiceProvider do
  @moduledoc false

  defstruct [:private_key, :certificate, :entity_id, :acs_url, :sls_url, :org, :sp_record]

  def new(org, attrs \\ %{}) do
    private_key = X509.PrivateKey.new_rsa(2048)

    certificate =
      X509.Certificate.self_signed(
        private_key,
        "/C=US/O=Test SP/CN=Test SAML SP",
        template: :server
      )

    key_pem = X509.PrivateKey.to_pem(private_key)
    cert_pem = X509.Certificate.to_pem(certificate)

    uid = :crypto.strong_rand_bytes(8) |> Base.hex_encode32(case: :lower)
    entity_id = Map.get(attrs, :entity_id, "https://sp-#{uid}.example.com")
    acs_url = Map.get(attrs, :acs_url, "#{entity_id}/saml/acs")
    sls_url = Map.get(attrs, :sls_url, "#{entity_id}/saml/sls")

    {:ok, sp_record} =
      Authify.SAML.create_service_provider(%{
        name: Map.get(attrs, :name, "Test SP #{uid}"),
        entity_id: entity_id,
        acs_url: acs_url,
        sls_url: sls_url,
        certificate: cert_pem,
        metadata: nil,
        attribute_mapping: Jason.encode!(%{}),
        sign_requests: true,
        sign_assertions: true,
        encrypt_assertions: false,
        is_active: true,
        organization_id: org.id
      })

    %__MODULE__{
      private_key: key_pem,
      certificate: cert_pem,
      entity_id: entity_id,
      acs_url: acs_url,
      sls_url: sls_url,
      org: org,
      sp_record: sp_record
    }
  end
end
