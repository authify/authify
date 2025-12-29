defmodule AuthifyWeb.API.OpenAPI.Schemas.Certificates do
  @moduledoc """
  OpenAPI schema definitions for certificates.
  """

  @doc """
  Returns the certificate-related schema definitions.
  """
  def build do
    %{
      "CertificateAttributes" => certificate_attributes(),
      "CertificateResource" => certificate_resource(),
      "CertificateResponse" => certificate_response(),
      "CertificatesCollectionResponse" => certificates_collection_response(),
      "CertificateCreateRequest" => certificate_create_request(),
      "CertificateUpdateRequest" => certificate_update_request()
    }
  end

  @doc """
  Example certificates list response data.
  """
  def certificates_list_example do
    %{
      data: [
        %{
          id: "301",
          type: "certificate",
          attributes: %{
            name: "Production SAML Signing Certificate",
            usage: "saml_signing",
            certificate:
              "-----BEGIN CERTIFICATE-----\nMIID...(truncated)...==\n-----END CERTIFICATE-----",
            expires_at: "2025-12-31T23:59:59Z",
            is_active: true,
            organization_id: 123,
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/certificates/301"
          }
        },
        %{
          id: "302",
          type: "certificate",
          attributes: %{
            name: "OAuth Signing Certificate",
            usage: "oauth_signing",
            certificate:
              "-----BEGIN CERTIFICATE-----\nMIID...(truncated)...==\n-----END CERTIFICATE-----",
            expires_at: "2026-06-15T23:59:59Z",
            is_active: true,
            organization_id: 123,
            inserted_at: "2024-02-15T10:00:00Z",
            updated_at: "2024-02-15T10:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/certificates/302"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/certificates?page=1&per_page=25",
        first: "/acme-corp/api/certificates?page=1&per_page=25"
      },
      meta: %{
        total: 2,
        page: 1,
        per_page: 25
      }
    }
  end

  @doc """
  Example certificate response data.
  """
  def certificate_example do
    %{
      data: %{
        id: "301",
        type: "certificate",
        attributes: %{
          name: "Production SAML Signing Certificate",
          usage: "saml_signing",
          certificate:
            "-----BEGIN CERTIFICATE-----\nMIID...(truncated)...==\n-----END CERTIFICATE-----",
          expires_at: "2025-12-31T23:59:59Z",
          is_active: true,
          organization_id: 123,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-01T00:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/certificates/301"
        }
      },
      links: %{
        self: "/acme-corp/api/certificates/301"
      }
    }
  end

  defp certificate_attributes do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "Certificate name"},
        usage: %{
          type: "string",
          enum: ["saml_signing", "saml_encryption", "oauth_signing"],
          description: "Certificate usage type"
        },
        certificate: %{
          type: "string",
          description: "PEM-encoded X.509 certificate"
        },
        expires_at: %{
          type: "string",
          format: "date-time",
          description: "Certificate expiration date (auto-extracted from certificate)"
        },
        is_active: %{
          type: "boolean",
          description: "Whether the certificate is active for use"
        },
        organization_id: %{type: "integer", description: "Organization ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp certificate_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Certificate ID"},
        type: %{type: "string", enum: ["certificate"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/CertificateAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp certificate_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/CertificateResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp certificates_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/CertificateResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp certificate_create_request do
    %{
      type: "object",
      properties: %{
        certificate: %{
          type: "object",
          properties: %{
            name: %{type: "string", description: "Certificate name"},
            usage: %{
              type: "string",
              enum: ["saml_signing", "saml_encryption", "oauth_signing"],
              description: "Certificate usage type"
            },
            generate_new: %{
              type: "string",
              enum: ["true"],
              description:
                "Set to 'true' to auto-generate a new self-signed certificate. If set, do not provide certificate or private_key."
            },
            certificate: %{
              type: "string",
              description:
                "PEM-encoded certificate (required for manual upload, omit if generate_new is true)"
            },
            private_key: %{
              type: "string",
              description:
                "PEM-encoded private key (required for manual upload, omit if generate_new is true)"
            },
            is_active: %{
              type: "boolean",
              default: true,
              description: "Whether certificate should be active immediately"
            }
          },
          required: ["name", "usage"]
        }
      },
      required: ["certificate"]
    }
  end

  defp certificate_update_request do
    %{
      type: "object",
      properties: %{
        certificate: %{
          type: "object",
          properties: %{
            name: %{type: "string", description: "Certificate name"}
          }
        }
      },
      required: ["certificate"]
    }
  end
end
