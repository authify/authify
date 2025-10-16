defmodule AuthifyWeb.API.DocsController do
  use AuthifyWeb, :controller

  def openapi(conn, _params) do
    # Get the base URL from the current request
    scheme = if conn.scheme == :https, do: "https", else: "http"
    host = get_req_header(conn, "host") |> List.first() || "localhost:4000"
    base_url = "#{scheme}://#{host}"

    # Generate the OpenAPI specification dynamically
    openapi_spec = %{
      openapi: "3.1.0",
      info: %{
        title: "Authify Management API",
        description: """
        Comprehensive REST API for managing Authify organizations, users, and OAuth applications.

        ## Features
        - **HATEOAS Compliance**: All responses include hypermedia links for navigation
        - **Header-based Versioning**: Use `Accept: application/vnd.authify.v1+json`
        - **Multi-tenant**: Organization-scoped access control
        - **Pagination**: Efficient pagination with navigation links
        - **Comprehensive Error Handling**: Structured error responses with validation details

        ## Authentication
        Use Bearer token authentication with a valid API token or session-based authentication.

        ## Rate Limiting
        API endpoints are rate-limited per organization. Limits and current usage are returned in response headers.
        """,
        version: "1.0.0",
        contact: %{
          name: "Authify API Support",
          url: "#{base_url}/developers/api"
        },
        license: %{
          name: "MIT",
          url: "https://opensource.org/licenses/MIT"
        }
      },
      servers: [
        %{
          url: base_url,
          description: "Current deployment"
        }
      ],
      security: [
        %{"BearerAuth" => []},
        %{"OAuth2" => []},
        %{"SessionAuth" => []}
      ],
      tags: [
        %{
          name: "Organization",
          description: "Organization profile and settings management"
        },
        %{
          name: "Users",
          description: "User management and role administration"
        },
        %{
          name: "Invitations",
          description: "User invitation management"
        },
        %{
          name: "Applications",
          description: "OAuth 2.0 application management"
        },
        %{
          name: "Application Groups",
          description: "Application group organization and management"
        },
        %{
          name: "Certificates",
          description: "SSL/TLS certificate management for SAML and OAuth signing"
        },
        %{
          name: "SAML Providers",
          description: "SAML 2.0 service provider configuration"
        },
        %{
          name: "Audit Logs",
          description: "Organization audit log access and filtering"
        },
        %{
          name: "Authentication",
          description: "API authentication and authorization"
        }
      ],
      paths: build_paths(),
      components: build_components(base_url)
    }

    conn
    |> put_resp_content_type("application/json")
    |> json(openapi_spec)
  end

  defp build_paths do
    %{
      "/{org_slug}/api/organization" => %{
        parameters: [
          %{"$ref" => "#/components/parameters/OrgSlug"},
          %{"$ref" => "#/components/parameters/AcceptHeader"}
        ],
        get: %{
          tags: ["Organization"],
          summary: "Get organization profile",
          description:
            "Retrieve the current organization's basic profile (name, slug, active status). For full configuration including branding and feature toggles, use /organization/configuration",
          security: [
            %{"OAuth2" => ["organizations:read"]},
            %{"BearerAuth" => []},
            %{"SessionAuth" => []}
          ],
          responses: %{
            "200" => %{
              description: "Organization profile retrieved successfully",
              content: %{
                "application/vnd.authify.v1+json" => %{
                  schema: %{"$ref" => "#/components/schemas/OrganizationResponse"},
                  example: organization_example()
                }
              }
            },
            "401" => %{"$ref" => "#/components/responses/Unauthorized"},
            "403" => %{"$ref" => "#/components/responses/Forbidden"}
          }
        }
      },
      "/{org_slug}/api/organization/configuration" => %{
        parameters: [
          %{"$ref" => "#/components/parameters/OrgSlug"},
          %{"$ref" => "#/components/parameters/AcceptHeader"}
        ],
        get: %{
          tags: ["Organization"],
          summary: "Get organization configuration",
          description:
            "Retrieve organization configuration settings. For authify-global organization, returns global settings (allow_organization_registration, site_name, support_email). For regular organizations, returns organization-specific settings (allow_invitations, allow_saml, allow_oauth, description, website_url, contact_email, logo_url).",
          security: [
            %{"OAuth2" => ["organizations:read"]},
            %{"BearerAuth" => []},
            %{"SessionAuth" => []}
          ],
          responses: %{
            "200" => %{
              description: "Configuration retrieved successfully",
              content: %{
                "application/vnd.authify.v1+json" => %{
                  schema: %{"$ref" => "#/components/schemas/ConfigurationResponse"}
                }
              }
            },
            "401" => %{"$ref" => "#/components/responses/Unauthorized"},
            "403" => %{"$ref" => "#/components/responses/Forbidden"}
          }
        },
        put: %{
          tags: ["Organization"],
          summary: "Update organization configuration",
          description:
            "Update organization configuration settings. Settings vary by organization: Global settings for authify-global (allow_organization_registration, site_name, support_email), Organization settings for regular orgs (allow_invitations, allow_saml, allow_oauth, description, website_url, contact_email, logo_url).",
          security: [
            %{"OAuth2" => ["organizations:write"]},
            %{"BearerAuth" => []},
            %{"SessionAuth" => []}
          ],
          requestBody: %{
            required: true,
            content: %{
              "application/json" => %{
                schema: %{"$ref" => "#/components/schemas/ConfigurationUpdateRequest"},
                examples: %{
                  global: %{
                    summary: "Update global settings (authify-global org)",
                    value: %{
                      settings: %{
                        allow_organization_registration: true,
                        site_name: "My Authify Instance",
                        support_email: "support@example.com"
                      }
                    }
                  },
                  organization: %{
                    summary: "Update organization settings (regular org)",
                    value: %{
                      settings: %{
                        allow_invitations: true,
                        allow_saml: true,
                        allow_oauth: true,
                        description: "Leading technology company",
                        website_url: "https://acme.com",
                        contact_email: "info@acme.com",
                        logo_url: "https://acme.com/logo.png"
                      }
                    }
                  }
                }
              }
            }
          },
          responses: %{
            "200" => %{
              description: "Configuration updated successfully",
              content: %{
                "application/vnd.authify.v1+json" => %{
                  schema: %{"$ref" => "#/components/schemas/ConfigurationResponse"}
                }
              }
            },
            "401" => %{"$ref" => "#/components/responses/Unauthorized"},
            "403" => %{"$ref" => "#/components/responses/Forbidden"},
            "422" => %{"$ref" => "#/components/responses/ValidationError"}
          }
        }
      },
      "/{org_slug}/api/users" => build_users_endpoints(),
      "/{org_slug}/api/users/{id}" => build_user_endpoints(),
      "/{org_slug}/api/users/{id}/role" => build_user_role_endpoints(),
      "/{org_slug}/api/invitations" => build_invitations_endpoints(),
      "/{org_slug}/api/invitations/{id}" => build_invitation_endpoints(),
      "/{org_slug}/api/applications" => build_applications_endpoints(),
      "/{org_slug}/api/applications/{id}" => build_application_endpoints(),
      "/{org_slug}/api/applications/{id}/regenerate-secret" => build_regenerate_secret_endpoint(),
      "/{org_slug}/api/application-groups" => build_application_groups_endpoints(),
      "/{org_slug}/api/application-groups/{id}" => build_application_group_endpoints(),
      "/{org_slug}/api/certificates" => build_certificates_endpoints(),
      "/{org_slug}/api/certificates/{id}" => build_certificate_endpoints(),
      "/{org_slug}/api/certificates/{id}/activate" => build_certificate_activate_endpoint(),
      "/{org_slug}/api/certificates/{id}/deactivate" => build_certificate_deactivate_endpoint(),
      "/{org_slug}/api/certificates/{id}/download/{type}" =>
        build_certificate_download_endpoint(),
      "/{org_slug}/api/audit-logs" => build_audit_logs_endpoints(),
      "/{org_slug}/api/audit-logs/{id}" => build_audit_log_endpoints()
    }
  end

  defp build_users_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Users"],
        summary: "List users",
        description: "Get a paginated list of users in the organization",
        security: [
          %{"OAuth2" => ["users:read"]},
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
            description: "Users retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UsersCollectionResponse"},
                example: users_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Users"],
        summary: "Create user",
        description: "Create a new user in the organization",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/UserCreateRequest"},
              example: %{
                user: %{
                  email: "jane@acme.com",
                  first_name: "Jane",
                  last_name: "Smith",
                  password: "SecureP@ssw0rd!",
                  password_confirmation: "SecureP@ssw0rd!"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "User created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp build_user_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Users"],
        summary: "Get user",
        description: "Retrieve a specific user's details",
        security: [
          %{"OAuth2" => ["users:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "User retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Users"],
        summary: "Update user",
        description: "Update a user's information",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/UserUpdateRequest"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "User updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
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
        tags: ["Users"],
        summary: "Delete user",
        description: "Delete a user from the organization",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "User deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_user_role_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      put: %{
        tags: ["Users"],
        summary: "Update user role",
        description: "Update a user's role in the organization",
        security: [
          %{"OAuth2" => ["users:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{
                type: "object",
                properties: %{
                  role: %{
                    type: "string",
                    enum: ["user", "admin"],
                    description: "New role for the user"
                  }
                },
                required: ["role"]
              },
              example: %{role: "admin"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "User role updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/UserResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp build_invitations_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Invitations"],
        summary: "List invitations",
        description:
          "Get a paginated list of invitations in the organization with optional status filtering",
        security: [
          %{"OAuth2" => ["invitations:read"]},
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
          },
          %{
            name: "status",
            in: "query",
            description: "Filter invitations by status",
            schema: %{type: "string", enum: ["pending", "accepted", "expired"]}
          }
        ],
        responses: %{
          "200" => %{
            description: "Invitations retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationsCollectionResponse"},
                example: invitations_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Invitations"],
        summary: "Create invitation",
        description: "Create a new invitation for a user to join the organization",
        security: [
          %{"OAuth2" => ["invitations:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/InvitationCreateRequest"},
              example: %{
                invitation: %{
                  email: "newuser@example.com",
                  role: "user"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Invitation created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationResponse"},
                example: invitation_create_example()
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp build_invitation_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Invitations"],
        summary: "Get invitation",
        description: "Retrieve a specific invitation's details",
        security: [
          %{"OAuth2" => ["invitations:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Invitation ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Invitation retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Invitations"],
        summary: "Update invitation",
        description: "Update an invitation's properties",
        security: [
          %{"OAuth2" => ["invitations:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Invitation ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/InvitationUpdateRequest"},
              example: %{
                invitation: %{
                  role: "admin"
                }
              }
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Invitation updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/InvitationResponse"}
              }
            }
          },
          "400" => %{"$ref" => "#/components/responses/BadRequest"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      },
      delete: %{
        tags: ["Invitations"],
        summary: "Delete invitation",
        description: "Delete/cancel an invitation",
        security: [
          %{"OAuth2" => ["invitations:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Invitation ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Invitation deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_applications_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Applications"],
        summary: "List OAuth applications",
        description: "Get a paginated list of OAuth applications in the organization",
        security: [
          %{"OAuth2" => ["applications:read"]},
          %{"OAuth2" => ["management_app:read"]},
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
            description: "Applications retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationsCollectionResponse"},
                example: applications_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Applications"],
        summary: "Create OAuth application",
        description: "Create a new OAuth application",
        security: [
          %{"OAuth2" => ["applications:write"]},
          %{"OAuth2" => ["management_app:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ApplicationCreateRequest"},
              example: %{
                application: %{
                  name: "Mobile App",
                  description: "Company mobile application",
                  redirect_uris: "com.acme.app://oauth/callback",
                  scopes: "openid profile email"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Application created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponseWithSecret"},
                example: application_with_secret_example()
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

  defp build_application_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Applications"],
        summary: "Get OAuth application",
        description: "Retrieve a specific OAuth application's details",
        security: [
          %{"OAuth2" => ["applications:read"]},
          %{"OAuth2" => ["management_app:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Application retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Applications"],
        summary: "Update OAuth application",
        description: "Update an OAuth application's configuration",
        security: [
          %{"OAuth2" => ["applications:write"]},
          %{"OAuth2" => ["management_app:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ApplicationUpdateRequest"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Application updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponse"}
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
        tags: ["Applications"],
        summary: "Delete OAuth application",
        description: "Delete an OAuth application",
        security: [
          %{"OAuth2" => ["applications:write"]},
          %{"OAuth2" => ["management_app:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Application deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_regenerate_secret_endpoint do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["Applications"],
        summary: "Regenerate client secret",
        description: "Generate a new client secret for the OAuth application",
        security: [
          %{"OAuth2" => ["applications:write"]},
          %{"OAuth2" => ["management_app:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Client secret regenerated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationResponseWithSecret"},
                example: regenerated_secret_example()
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

  defp build_application_groups_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Application Groups"],
        summary: "List application groups",
        description: "Get a paginated list of application groups in the organization",
        security: [
          %{"OAuth2" => ["application_groups:read"]},
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
            description: "Application groups retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationGroupsCollectionResponse"},
                example: application_groups_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Application Groups"],
        summary: "Create application group",
        description: "Create a new application group to organize OAuth applications",
        security: [
          %{"OAuth2" => ["application_groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ApplicationGroupCreateRequest"},
              example: %{
                application_group: %{
                  name: "Mobile Apps",
                  description: "All mobile applications for iOS and Android"
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Application group created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationGroupResponse"},
                example: application_group_example()
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

  defp build_application_group_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Application Groups"],
        summary: "Get application group",
        description: "Retrieve a specific application group's details",
        security: [
          %{"OAuth2" => ["application_groups:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application Group ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Application group retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationGroupResponse"}
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Application Groups"],
        summary: "Update application group",
        description: "Update an application group's details",
        security: [
          %{"OAuth2" => ["application_groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application Group ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/ApplicationGroupUpdateRequest"}
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Application group updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/ApplicationGroupResponse"}
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
        tags: ["Application Groups"],
        summary: "Delete application group",
        description: "Delete an application group",
        security: [
          %{"OAuth2" => ["application_groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Application Group ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Application group deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp build_components(base_url) do
    %{
      securitySchemes: %{
        "BearerAuth" => %{
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description:
            "OAuth2 Bearer token or Personal Access Token authentication. Include token in Authorization header as 'Bearer <token>'."
        },
        "OAuth2" => %{
          type: "oauth2",
          description:
            "OAuth2 authentication with granular scopes for API access. Use the Client Credentials flow with Management API applications to programmatically access the API with client_id and client_secret.",
          flows: %{
            authorizationCode: %{
              authorizationUrl: "#{base_url}/{org_slug}/oauth/authorize",
              tokenUrl: "#{base_url}/{org_slug}/oauth/token",
              scopes: %{
                "applications:read" => "Read OAuth2 applications",
                "applications:write" => "Manage OAuth2 applications",
                "application_groups:read" => "Read application groups",
                "application_groups:write" => "Manage application groups",
                "certificates:read" => "Read certificates",
                "certificates:write" => "Manage certificates",
                "invitations:read" => "Read invitations",
                "invitations:write" => "Manage invitations",
                "management_app:read" => "Read Management API applications",
                "management_app:write" => "Manage Management API applications",
                "organizations:read" => "Read organization configuration",
                "organizations:write" => "Manage organization configuration",
                "saml:read" => "Read SAML service providers",
                "saml:write" => "Manage SAML service providers",
                "users:read" => "Read users",
                "users:write" => "Manage users"
              }
            },
            clientCredentials: %{
              tokenUrl: "#{base_url}/{org_slug}/oauth/token",
              scopes: %{
                "applications:read" => "Read OAuth2 applications",
                "applications:write" => "Manage OAuth2 applications",
                "application_groups:read" => "Read application groups",
                "application_groups:write" => "Manage application groups",
                "certificates:read" => "Read certificates",
                "certificates:write" => "Manage certificates",
                "invitations:read" => "Read invitations",
                "invitations:write" => "Manage invitations",
                "management_app:read" => "Read Management API applications",
                "management_app:write" => "Manage Management API applications",
                "organizations:read" => "Read organization configuration",
                "organizations:write" => "Manage organization configuration",
                "saml:read" => "Read SAML service providers",
                "saml:write" => "Manage SAML service providers",
                "users:read" => "Read users",
                "users:write" => "Manage users"
              }
            }
          }
        },
        "SessionAuth" => %{
          type: "apiKey",
          in: "cookie",
          name: "_authify_session",
          description:
            "Session-based authentication for web browsers. Automatically grants all API scopes."
        }
      },
      parameters: %{
        "OrgSlug" => %{
          name: "org_slug",
          in: "path",
          required: true,
          description: "Organization slug identifier",
          schema: %{
            type: "string",
            pattern: "^[a-z0-9-]+$",
            example: "my-organization"
          }
        },
        "AcceptHeader" => %{
          name: "Accept",
          in: "header",
          required: true,
          description:
            "API version negotiation. Use 'application/vnd.authify.v1+json' for versioned responses or 'application/json' for default version.",
          schema: %{
            type: "string",
            enum: ["application/vnd.authify.v1+json", "application/json"],
            default: "application/vnd.authify.v1+json"
          }
        }
      },
      schemas: build_schemas(),
      responses: build_responses(base_url)
    }
  end

  defp build_schemas do
    %{
      # HATEOAS and Pagination
      "HateoasLink" => %{
        type: "object",
        properties: %{
          self: %{type: "string", format: "uri", description: "Link to the current resource"},
          next: %{
            type: "string",
            format: "uri",
            description: "Link to the next page (pagination)"
          },
          prev: %{
            type: "string",
            format: "uri",
            description: "Link to the previous page (pagination)"
          },
          first: %{
            type: "string",
            format: "uri",
            description: "Link to the first page (pagination)"
          },
          last: %{
            type: "string",
            format: "uri",
            description: "Link to the last page (pagination)"
          }
        },
        required: ["self"]
      },
      "PaginationMeta" => %{
        type: "object",
        properties: %{
          total: %{type: "integer", description: "Total number of items"},
          page: %{type: "integer", description: "Current page number"},
          per_page: %{type: "integer", description: "Number of items per page"}
        },
        required: ["total", "page", "per_page"]
      },
      # Organization schemas
      "OrganizationAttributes" => build_organization_attributes_schema(),
      "OrganizationResource" => build_organization_resource_schema(),
      "OrganizationResponse" => build_organization_response_schema(),
      "ConfigurationResponse" => build_configuration_response_schema(),
      "ConfigurationUpdateRequest" => build_configuration_update_request_schema(),
      # User schemas
      "UserAttributes" => build_user_attributes_schema(),
      "UserResource" => build_user_resource_schema(),
      "UserResponse" => build_user_response_schema(),
      "UsersCollectionResponse" => build_users_collection_response_schema(),
      "UserCreateRequest" => build_user_create_request_schema(),
      "UserUpdateRequest" => build_user_update_request_schema(),
      # Invitation schemas
      "InvitationAttributes" => build_invitation_attributes_schema(),
      "InvitationResource" => build_invitation_resource_schema(),
      "InvitationResponse" => build_invitation_response_schema(),
      "InvitationsCollectionResponse" => build_invitations_collection_response_schema(),
      "InvitationCreateRequest" => build_invitation_create_request_schema(),
      "InvitationUpdateRequest" => build_invitation_update_request_schema(),
      # Application schemas
      "ApplicationAttributes" => build_application_attributes_schema(),
      "ApplicationAttributesWithSecret" => build_application_attributes_with_secret_schema(),
      "ApplicationResource" => build_application_resource_schema(),
      "ApplicationResourceWithSecret" => build_application_resource_with_secret_schema(),
      "ApplicationResponse" => build_application_response_schema(),
      "ApplicationResponseWithSecret" => build_application_response_with_secret_schema(),
      "ApplicationsCollectionResponse" => build_applications_collection_response_schema(),
      "ApplicationCreateRequest" => build_application_create_request_schema(),
      "ApplicationUpdateRequest" => build_application_update_request_schema(),
      # Application Group schemas
      "ApplicationGroupAttributes" => build_application_group_attributes_schema(),
      "ApplicationGroupResource" => build_application_group_resource_schema(),
      "ApplicationGroupResponse" => build_application_group_response_schema(),
      "ApplicationGroupsCollectionResponse" =>
        build_application_groups_collection_response_schema(),
      "ApplicationGroupCreateRequest" => build_application_group_create_request_schema(),
      "ApplicationGroupUpdateRequest" => build_application_group_update_request_schema(),
      # Error schemas
      "ErrorResponse" => build_error_response_schema()
    }
  end

  # Schema building functions
  defp build_organization_attributes_schema do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "Organization name"},
        slug: %{type: "string", description: "Organization slug (URL-friendly identifier)"},
        active: %{type: "boolean", description: "Whether the organization is active"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp build_organization_resource_schema do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Organization ID"},
        type: %{type: "string", enum: ["organization"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/OrganizationAttributes"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp build_organization_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/OrganizationResource"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["data", "links"]
    }
  end

  defp build_configuration_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{
          type: "object",
          properties: %{
            id: %{type: "string", format: "uuid", description: "Organization ID"},
            type: %{type: "string", example: "configuration"},
            attributes: %{
              type: "object",
              properties: %{
                id: %{type: "integer", description: "Organization ID"},
                schema_name: %{
                  type: "string",
                  enum: ["global", "organization"],
                  description:
                    "Schema name: 'global' for authify-global org, 'organization' for regular orgs"
                },
                settings: %{
                  type: "object",
                  description: "Configuration settings (varies by schema)",
                  example: %{
                    allow_organization_registration: false,
                    site_name: "Authify",
                    support_email: "support@example.com"
                  }
                },
                updated_at: %{
                  type: "string",
                  format: "date-time",
                  description: "Last update timestamp"
                }
              },
              required: ["id", "schema_name", "settings"]
            }
          }
        },
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["data", "links"]
    }
  end

  defp build_configuration_update_request_schema do
    %{
      type: "object",
      properties: %{
        settings: %{
          type: "object",
          description: "Configuration settings to update (varies by organization schema)",
          oneOf: [
            %{
              description: "Global settings (authify-global organization)",
              properties: %{
                allow_organization_registration: %{
                  type: "boolean",
                  description: "Allow new organizations to self-register"
                },
                site_name: %{type: "string", description: "Name of the Authify instance"},
                support_email: %{
                  type: "string",
                  format: "email",
                  description: "Support contact email"
                }
              }
            },
            %{
              description: "Organization settings (regular organizations)",
              properties: %{
                allow_invitations: %{
                  type: "boolean",
                  description: "Allow admins to invite new users"
                },
                allow_saml: %{type: "boolean", description: "Enable SAML 2.0 identity provider"},
                allow_oauth: %{
                  type: "boolean",
                  description: "Enable OAuth2/OIDC identity provider"
                },
                description: %{
                  type: "string",
                  description: "Organization description (max 1000 chars)"
                },
                website_url: %{
                  type: "string",
                  format: "uri",
                  description: "Organization website URL"
                },
                contact_email: %{
                  type: "string",
                  format: "email",
                  description: "Organization contact email"
                },
                logo_url: %{type: "string", format: "uri", description: "Organization logo URL"}
              }
            }
          ]
        }
      },
      required: ["settings"]
    }
  end

  defp build_user_attributes_schema do
    %{
      type: "object",
      properties: %{
        email: %{type: "string", format: "email", description: "User email address"},
        first_name: %{type: "string", nullable: true, description: "User first name"},
        last_name: %{type: "string", nullable: true, description: "User last name"},
        active: %{type: "boolean", description: "Whether the user is active"},
        email_confirmed_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "Email confirmation timestamp"
        },
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp build_user_resource_schema do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "User ID"},
        type: %{type: "string", enum: ["user"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/UserAttributes"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp build_user_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/UserResource"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["data", "links"]
    }
  end

  defp build_users_collection_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/UserResource"}},
        links: %{"$ref" => "#/components/schemas/HateoasLink"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp build_user_create_request_schema do
    %{
      type: "object",
      properties: %{
        user: %{
          type: "object",
          properties: %{
            email: %{type: "string", format: "email"},
            first_name: %{type: "string"},
            last_name: %{type: "string"},
            password: %{
              type: "string",
              minLength: 8,
              description: "Must contain uppercase, lowercase, number, and special character"
            },
            password_confirmation: %{type: "string", description: "Must match password"}
          },
          required: ["email", "password", "password_confirmation"]
        }
      },
      required: ["user"]
    }
  end

  defp build_user_update_request_schema do
    %{
      type: "object",
      properties: %{
        user: %{
          type: "object",
          properties: %{
            first_name: %{type: "string"},
            last_name: %{type: "string"},
            active: %{type: "boolean"}
          }
        }
      },
      required: ["user"]
    }
  end

  defp build_invitation_attributes_schema do
    %{
      type: "object",
      properties: %{
        email: %{type: "string", format: "email", description: "Invitee's email address"},
        role: %{type: "string", enum: ["user", "admin"], description: "Role to be assigned"},
        expires_at: %{
          type: "string",
          format: "date-time",
          description: "Invitation expiration time"
        },
        accepted_at: %{
          type: "string",
          format: "date-time",
          nullable: true,
          description: "When the invitation was accepted"
        },
        created_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp build_invitation_resource_schema do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Invitation ID"},
        type: %{type: "string", enum: ["invitation"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/InvitationAttributes"},
        links: %{
          type: "object",
          properties: %{
            self: %{type: "string", format: "uri", description: "Link to this invitation"}
          },
          required: ["self"]
        }
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp build_invitation_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/InvitationResource"}
      },
      required: ["data"]
    }
  end

  defp build_invitations_collection_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{
          type: "array",
          items: %{"$ref" => "#/components/schemas/InvitationResource"}
        },
        links: %{"$ref" => "#/components/schemas/HateoasLink"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp build_invitation_create_request_schema do
    %{
      type: "object",
      properties: %{
        invitation: %{
          type: "object",
          properties: %{
            email: %{type: "string", format: "email", description: "Invitee's email address"},
            role: %{type: "string", enum: ["user", "admin"], description: "Role to be assigned"}
          },
          required: ["email", "role"]
        }
      },
      required: ["invitation"]
    }
  end

  defp build_invitation_update_request_schema do
    %{
      type: "object",
      properties: %{
        invitation: %{
          type: "object",
          properties: %{
            role: %{type: "string", enum: ["user", "admin"], description: "Updated role"}
          }
        }
      },
      required: ["invitation"]
    }
  end

  defp build_application_attributes_schema do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "Application name"},
        client_id: %{type: "string", description: "OAuth client identifier"},
        description: %{type: "string", nullable: true, description: "Application description"},
        redirect_uris: %{type: "string", description: "Newline-separated list of redirect URIs"},
        scopes: %{type: "string", description: "Space-separated list of OAuth scopes"},
        is_active: %{type: "boolean", description: "Whether the application is active"},
        organization_id: %{type: "integer", description: "Organization ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp build_application_attributes_with_secret_schema do
    %{
      allOf: [
        %{"$ref" => "#/components/schemas/ApplicationAttributes"},
        %{
          type: "object",
          properties: %{
            client_secret: %{
              type: "string",
              description: "OAuth client secret (only shown on creation and regeneration)"
            }
          }
        }
      ]
    }
  end

  defp build_application_resource_schema do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Application ID"},
        type: %{type: "string", enum: ["application"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ApplicationAttributes"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp build_application_resource_with_secret_schema do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Application ID"},
        type: %{type: "string", enum: ["application"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ApplicationAttributesWithSecret"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp build_application_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/ApplicationResource"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["data", "links"]
    }
  end

  defp build_application_response_with_secret_schema do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/ApplicationResourceWithSecret"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["data", "links"]
    }
  end

  defp build_applications_collection_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/ApplicationResource"}},
        links: %{"$ref" => "#/components/schemas/HateoasLink"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp build_application_create_request_schema do
    %{
      type: "object",
      properties: %{
        application: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255},
            description: %{type: "string", nullable: true},
            redirect_uris: %{
              type: "string",
              description: "Newline-separated list of valid redirect URIs"
            },
            scopes: %{
              type: "string",
              default: "openid profile email",
              description: "Space-separated list of OAuth scopes"
            }
          },
          required: ["name", "redirect_uris"]
        }
      },
      required: ["application"]
    }
  end

  defp build_application_update_request_schema do
    %{
      type: "object",
      properties: %{
        application: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255},
            description: %{type: "string", nullable: true},
            redirect_uris: %{
              type: "string",
              description: "Newline-separated list of valid redirect URIs"
            },
            scopes: %{type: "string", description: "Space-separated list of OAuth scopes"},
            is_active: %{type: "boolean"}
          }
        }
      },
      required: ["application"]
    }
  end

  defp build_application_group_attributes_schema do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "Application group name"},
        description: %{
          type: "string",
          nullable: true,
          description: "Application group description"
        },
        organization_id: %{type: "integer", description: "Organization ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp build_application_group_resource_schema do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Application Group ID"},
        type: %{type: "string", enum: ["application_group"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/ApplicationGroupAttributes"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp build_application_group_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/ApplicationGroupResource"},
        links: %{"$ref" => "#/components/schemas/HateoasLink"}
      },
      required: ["data", "links"]
    }
  end

  defp build_application_groups_collection_response_schema do
    %{
      type: "object",
      properties: %{
        data: %{
          type: "array",
          items: %{"$ref" => "#/components/schemas/ApplicationGroupResource"}
        },
        links: %{"$ref" => "#/components/schemas/HateoasLink"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp build_application_group_create_request_schema do
    %{
      type: "object",
      properties: %{
        application_group: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255},
            description: %{type: "string", nullable: true}
          },
          required: ["name"]
        }
      },
      required: ["application_group"]
    }
  end

  defp build_application_group_update_request_schema do
    %{
      type: "object",
      properties: %{
        application_group: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255},
            description: %{type: "string", nullable: true}
          }
        }
      },
      required: ["application_group"]
    }
  end

  defp build_error_response_schema do
    %{
      type: "object",
      properties: %{
        error: %{
          type: "object",
          properties: %{
            type: %{type: "string", description: "Error type identifier"},
            message: %{type: "string", description: "Human-readable error message"},
            details: %{
              type: "object",
              description: "Additional error details (e.g., validation errors)"
            }
          },
          required: ["type", "message"]
        },
        links: %{
          type: "object",
          properties: %{
            documentation: %{
              type: "string",
              format: "uri",
              description: "Link to error documentation"
            }
          }
        }
      },
      required: ["error", "links"]
    }
  end

  defp build_responses(base_url) do
    %{
      "BadRequest" => %{
        description: "Bad request - invalid request format",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "bad_request",
                message: "Invalid request format"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "Unauthorized" => %{
        description: "Unauthorized - authentication required",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "unauthorized",
                message: "Authentication required"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "Forbidden" => %{
        description: "Forbidden - insufficient permissions",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "forbidden",
                message: "Insufficient permissions"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "NotFound" => %{
        description: "Not found - resource not found",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "resource_not_found",
                message: "Resource not found in organization"
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      },
      "ValidationError" => %{
        description: "Validation error - request data failed validation",
        content: %{
          "application/vnd.authify.v1+json" => %{
            schema: %{"$ref" => "#/components/schemas/ErrorResponse"},
            example: %{
              error: %{
                type: "validation_failed",
                message: "The request data failed validation",
                details: %{
                  email: ["is required"],
                  password: ["must be at least 8 characters"]
                }
              },
              links: %{
                documentation: "#{base_url}/developers/errors"
              }
            }
          }
        }
      }
    }
  end

  # Example data functions
  defp organization_example do
    %{
      data: %{
        id: "123",
        type: "organization",
        attributes: %{
          name: "Acme Corp",
          slug: "acme-corp",
          active: true,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-01T00:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/organization"
        }
      },
      links: %{
        self: "/acme-corp/api/organization"
      }
    }
  end

  defp users_list_example do
    %{
      data: [
        %{
          id: "456",
          type: "user",
          attributes: %{
            email: "john@acme.com",
            first_name: "John",
            last_name: "Doe",
            active: true,
            email_confirmed_at: "2024-01-01T00:00:00Z",
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/users/456"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/users?page=1&per_page=25",
        first: "/acme-corp/api/users?page=1&per_page=25",
        next: "/acme-corp/api/users?page=2&per_page=25",
        last: "/acme-corp/api/users?page=10&per_page=25"
      },
      meta: %{
        total: 250,
        page: 1,
        per_page: 25
      }
    }
  end

  defp invitations_list_example do
    %{
      data: [
        %{
          id: "456",
          type: "invitation",
          attributes: %{
            email: "pending@example.com",
            role: "user",
            expires_at: "2024-12-31T23:59:59Z",
            accepted_at: nil,
            created_at: "2024-01-15T10:30:00Z",
            updated_at: "2024-01-15T10:30:00Z"
          },
          links: %{
            self: "/acme-corp/api/invitations/456"
          }
        },
        %{
          id: "457",
          type: "invitation",
          attributes: %{
            email: "admin@example.com",
            role: "admin",
            expires_at: "2024-12-31T23:59:59Z",
            accepted_at: "2024-01-20T14:30:00Z",
            created_at: "2024-01-10T09:00:00Z",
            updated_at: "2024-01-20T14:30:00Z"
          },
          links: %{
            self: "/acme-corp/api/invitations/457"
          }
        }
      ],
      links: %{
        self: "http://localhost:4002/acme-corp/api/invitations",
        first: "http://localhost:4002/acme-corp/api/invitations?page=1&per_page=25"
      },
      meta: %{
        total: 2,
        page: 1,
        per_page: 25
      }
    }
  end

  defp invitation_create_example do
    %{
      data: %{
        id: "458",
        type: "invitation",
        attributes: %{
          email: "newuser@example.com",
          role: "user",
          expires_at: "2024-12-31T23:59:59Z",
          accepted_at: nil,
          created_at: "2024-01-25T15:30:00Z",
          updated_at: "2024-01-25T15:30:00Z"
        },
        links: %{
          self: "/acme-corp/api/invitations/458"
        }
      }
    }
  end

  defp applications_list_example do
    %{
      data: [
        %{
          id: "789",
          type: "application",
          attributes: %{
            name: "Web App",
            client_id: "client_123456",
            description: "Main web application",
            redirect_uris: "https://app.acme.com/callback",
            scopes: "openid profile email",
            is_active: true,
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/applications/789"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/applications?page=1&per_page=25",
        first: "/acme-corp/api/applications?page=1&per_page=25"
      },
      meta: %{
        total: 5,
        page: 1,
        per_page: 25
      }
    }
  end

  defp application_with_secret_example do
    %{
      data: %{
        id: "790",
        type: "application",
        attributes: %{
          name: "Mobile App",
          client_id: "client_789012",
          client_secret: "secret_abcdef123456",
          description: "Company mobile application",
          redirect_uris: "com.acme.app://oauth/callback",
          scopes: "openid profile email",
          is_active: true,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-01T00:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/applications/790"
        }
      },
      links: %{
        self: "/acme-corp/api/applications/790"
      }
    }
  end

  defp regenerated_secret_example do
    %{
      data: %{
        id: "789",
        type: "application",
        attributes: %{
          name: "Web App",
          client_id: "client_123456",
          client_secret: "new_secret_xyz789",
          description: "Main web application",
          redirect_uris: "https://app.acme.com/callback",
          scopes: "openid profile email",
          is_active: true,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-01T12:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/applications/789"
        }
      },
      links: %{
        self: "/acme-corp/api/applications/789"
      }
    }
  end

  defp application_groups_list_example do
    %{
      data: [
        %{
          id: "100",
          type: "application_group",
          attributes: %{
            name: "Mobile Apps",
            description: "All mobile applications for iOS and Android",
            organization_id: 1,
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/application-groups/100"
          }
        },
        %{
          id: "101",
          type: "application_group",
          attributes: %{
            name: "Web Applications",
            description: "Web-based applications",
            organization_id: 1,
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/application-groups/101"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/application-groups?page=1&per_page=25",
        first: "/acme-corp/api/application-groups?page=1&per_page=25"
      },
      meta: %{
        total: 2,
        page: 1,
        per_page: 25
      }
    }
  end

  defp application_group_example do
    %{
      data: %{
        id: "100",
        type: "application_group",
        attributes: %{
          name: "Mobile Apps",
          description: "All mobile applications for iOS and Android",
          organization_id: 1,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-01T00:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/application-groups/100"
        }
      },
      links: %{
        self: "/acme-corp/api/application-groups/100"
      }
    }
  end

  # Certificate endpoint builders
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
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{type: "array", items: %{type: "object"}},
                    links: %{type: "object"},
                    meta: %{type: "object"}
                  }
                }
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
              schema: %{
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
                        description: "Set to 'true' to generate new certificate automatically"
                      },
                      certificate: %{
                        type: "string",
                        description: "PEM-encoded certificate (for manual upload)"
                      },
                      private_key: %{
                        type: "string",
                        description: "PEM-encoded private key (for manual upload)"
                      },
                      is_active: %{
                        type: "boolean",
                        default: true,
                        description: "Whether certificate is active"
                      }
                    },
                    required: ["name", "usage"]
                  }
                },
                required: ["certificate"]
              }
            }
          }
        },
        responses: %{
          "201" => %{description: "Certificate created successfully"},
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
          "200" => %{description: "Certificate retrieved successfully"},
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
              schema: %{
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
            }
          }
        },
        responses: %{
          "200" => %{description: "Certificate updated successfully"},
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
          "200" => %{description: "Certificate activated successfully"},
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
          "200" => %{description: "Certificate deactivated successfully"},
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

  defp build_audit_logs_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Audit Logs"],
        summary: "List audit logs",
        description:
          "Get a paginated list of audit log entries for the organization with optional filtering. Requires `audit_logs:read` scope.",
        security: [
          %{"OAuth2" => ["audit_logs:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "page",
            in: "query",
            required: false,
            description: "Page number (default: 1)",
            schema: %{type: "integer", minimum: 1, default: 1}
          },
          %{
            name: "per_page",
            in: "query",
            required: false,
            description: "Results per page (default: 25, max: 100)",
            schema: %{type: "integer", minimum: 1, maximum: 100, default: 25}
          },
          %{
            name: "event_type",
            in: "query",
            required: false,
            description:
              "Filter by event type (e.g., 'user_created', 'login_success', 'oauth_client_created')",
            schema: %{type: "string"}
          },
          %{
            name: "actor_id",
            in: "query",
            required: false,
            description: "Filter by actor ID",
            schema: %{type: "string"}
          },
          %{
            name: "actor_type",
            in: "query",
            required: false,
            description: "Filter by actor type",
            schema: %{type: "string", enum: ["user", "api_client", "application", "system"]}
          },
          %{
            name: "resource_type",
            in: "query",
            required: false,
            description:
              "Filter by resource type (e.g., 'user', 'oauth_application', 'invitation')",
            schema: %{type: "string"}
          },
          %{
            name: "resource_id",
            in: "query",
            required: false,
            description: "Filter by resource ID",
            schema: %{type: "string"}
          },
          %{
            name: "outcome",
            in: "query",
            required: false,
            description: "Filter by outcome",
            schema: %{type: "string", enum: ["success", "failure", "denied"]}
          },
          %{
            name: "from_date",
            in: "query",
            required: false,
            description: "Filter events after this date (ISO 8601 format)",
            schema: %{type: "string", format: "date-time"}
          },
          %{
            name: "to_date",
            in: "query",
            required: false,
            description: "Filter events before this date (ISO 8601 format)",
            schema: %{type: "string", format: "date-time"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Audit logs retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{
                      type: "array",
                      items: %{
                        type: "object",
                        properties: %{
                          id: %{type: "string"},
                          type: %{type: "string", example: "audit_log"},
                          attributes: %{
                            type: "object",
                            properties: %{
                              event_type: %{type: "string"},
                              actor_type: %{type: "string"},
                              actor_id: %{type: "string"},
                              actor_name: %{type: "string"},
                              resource_type: %{type: "string"},
                              resource_id: %{type: "string"},
                              outcome: %{type: "string"},
                              ip_address: %{type: "string"},
                              user_agent: %{type: "string"},
                              metadata: %{type: "object"},
                              inserted_at: %{type: "string", format: "date-time"}
                            }
                          }
                        }
                      }
                    },
                    meta: %{
                      type: "object",
                      properties: %{
                        page: %{type: "integer"},
                        per_page: %{type: "integer"},
                        total: %{type: "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      }
    }
  end

  defp build_audit_log_endpoints do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Audit Logs"],
        summary: "Get audit log entry",
        description: "Get a specific audit log entry by ID. Requires `audit_logs:read` scope.",
        security: [
          %{"OAuth2" => ["audit_logs:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Audit log entry ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Audit log entry retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{
                      type: "object",
                      properties: %{
                        id: %{type: "string"},
                        type: %{type: "string", example: "audit_log"},
                        attributes: %{
                          type: "object",
                          properties: %{
                            event_type: %{type: "string"},
                            actor_type: %{type: "string"},
                            actor_id: %{type: "string"},
                            actor_name: %{type: "string"},
                            resource_type: %{type: "string"},
                            resource_id: %{type: "string"},
                            outcome: %{type: "string"},
                            ip_address: %{type: "string"},
                            user_agent: %{type: "string"},
                            metadata: %{type: "object"},
                            inserted_at: %{type: "string", format: "date-time"}
                          }
                        }
                      }
                    }
                  }
                }
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
end
