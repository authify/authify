defmodule AuthifyWeb.API.OpenAPI.Paths.Certificates do
  @moduledoc """
  OpenAPI path definitions for Certificate endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Certificates

  def build do
    %{
      "/organizations/{org_slug}/certificates" => build_certificates_endpoints(),
      "/organizations/{org_slug}/certificates/{id}" => build_certificate_endpoints(),
      "/organizations/{org_slug}/certificates/{id}/activate" =>
        build_certificate_activate_endpoint(),
      "/organizations/{org_slug}/certificates/{id}/deactivate" =>
        build_certificate_deactivate_endpoint(),
      "/organizations/{org_slug}/certificates/{id}/download/{type}" =>
        build_certificate_download_endpoint()
    }
  end

  defp build_certificates_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Certificates"],
        summary: "List certificates",
        description:
          "Get a paginated list of certificates in the organization. Requires `certificates:read` scope.",
        security: [
          %{"OAuth2" => ["certificates:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "page",
            in: "query",
            description: "Page number (1-based)",
            schema: %{type: "integer", minimum: 1, default: 1}
          },
          %{
            name: "per_page",
            in: "query",
            description: "Number of items per page",
            schema: %{type: "integer", minimum: 1, maximum: 100, default: 25}
          }
        ],
        responses: %{
          "200" => %{
            description: "Certificates retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/CertificatesCollectionResponse"},
                example: Certificates.certificates_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Certificates"],
        summary: "Create certificate",
        description:
          "Create a new certificate or generate one automatically. Requires `certificates:write` scope.",
        security: [
          %{"OAuth2" => ["certificates:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/CertificateCreateRequest"}
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Certificate created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/CertificateResponse"},
                example: Certificates.certificate_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp build_certificate_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Certificates"],
        summary: "Get certificate",
        description:
          "Retrieve a specific certificate's details. Requires `certificates:read` scope.",
        security: [
          %{"OAuth2" => ["certificates:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Certificate ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Certificate retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/CertificateResponse"},
                example: Certificates.certificate_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Certificates"],
        summary: "Update certificate",
        description: "Update a certificate's metadata. Requires `certificates:write` scope.",
        security: [
          %{"OAuth2" => ["certificates:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Certificate ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/CertificateUpdateRequest"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Certificate updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/CertificateResponse"},
                example: Certificates.certificate_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      },
      delete: %{
        tags: ["Certificates"],
        summary: "Delete certificate",
        description:
          "Delete a certificate from the organization. Requires `certificates:write` scope.",
        security: [
          %{"OAuth2" => ["certificates:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Certificate ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Certificate deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_certificate_activate_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      patch: %{
        tags: ["Certificates"],
        summary: "Activate certificate",
        description: "Activate a certificate for use. Requires `certificates:write` scope.",
        security: [
          %{"OAuth2" => ["certificates:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Certificate ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Certificate activated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/CertificateResponse"},
                example: Certificates.certificate_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_certificate_deactivate_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      patch: %{
        tags: ["Certificates"],
        summary: "Deactivate certificate",
        description: "Deactivate a certificate. Requires `certificates:write` scope.",
        security: [
          %{"OAuth2" => ["certificates:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Certificate ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Certificate deactivated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/CertificateResponse"},
                example: Certificates.certificate_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_certificate_download_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Certificates"],
        summary: "Download certificate or private key",
        description:
          "Download the certificate or private key file. Requires `certificates:write` scope for private key access.",
        security: [
          %{"OAuth2" => ["certificates:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Certificate ID",
            schema: %{type: "string"}
          },
          %{
            name: "type",
            in: "path",
            required: true,
            description: "Download type",
            schema: %{type: "string", enum: ["certificate", "private_key"]}
          }
        ],
        responses: %{
          "200" => %{
            description: "File downloaded successfully",
            content: %{
              "application/x-pem-file" => %{
                schema: %{
                  type: "string",
                  format: "binary"
                }
              }
            },
            headers: %{
              "Content-Disposition" => %{
                schema: %{type: "string"},
                description: "Attachment filename"
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end
end
