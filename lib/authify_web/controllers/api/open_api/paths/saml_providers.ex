defmodule AuthifyWeb.API.OpenAPI.Paths.SamlProviders do
  @moduledoc """
  OpenAPI path definitions for SAML Provider endpoints.
  """

  def build do
    %{
      "/api/orgs/{org_slug}/saml_providers" => build_saml_providers_collection(),
      "/api/orgs/{org_slug}/saml_providers/{id}" => build_saml_provider_resource()
    }
  end

  defp build_saml_providers_collection do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: build_list_saml_providers(),
      post: build_create_saml_provider()
    }
  end

  defp build_saml_provider_resource do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: build_get_saml_provider(),
      put: build_update_saml_provider(),
      delete: build_delete_saml_provider()
    }
  end

  defp build_list_saml_providers do
    %{
      tags: ["SAML Providers"],
      summary: "List SAML providers",
      description:
        "Get a paginated list of SAML 2.0 service providers configured in the organization. Requires `saml:read` scope.",
      security: [
        %{"OAuth2" => ["saml:read"]},
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
          description: "SAML providers retrieved successfully",
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
                        type: %{type: "string", example: "service_provider"},
                        attributes: %{
                          type: "object",
                          properties: %{
                            name: %{type: "string"},
                            entity_id: %{type: "string"},
                            acs_url: %{type: "string", format: "uri"},
                            slo_url: %{type: "string", format: "uri", nullable: true},
                            attribute_mapping: %{type: "object"},
                            inserted_at: %{type: "string", format: "date-time"},
                            updated_at: %{type: "string", format: "date-time"}
                          }
                        }
                      }
                    }
                  },
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
    }
  end

  defp build_create_saml_provider do
    %{
      tags: ["SAML Providers"],
      summary: "Create SAML provider",
      description:
        "Register a new SAML 2.0 service provider in the organization. Requires `saml:write` scope.",
      security: [
        %{"OAuth2" => ["saml:write"]},
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
                saml_provider: %{
                  type: "object",
                  properties: %{
                    name: %{
                      type: "string",
                      description: "Human-readable name for the service provider"
                    },
                    entity_id: %{
                      type: "string",
                      format: "uri",
                      description: "Unique identifier for the service provider (usually a URL)"
                    },
                    acs_url: %{
                      type: "string",
                      format: "uri",
                      description:
                        "Assertion Consumer Service URL (where SAML responses are sent)"
                    },
                    slo_url: %{
                      type: "string",
                      format: "uri",
                      nullable: true,
                      description:
                        "Single Logout URL (optional, for logout coordination with the SP)"
                    },
                    attribute_mapping: %{
                      type: "object",
                      description:
                        "Maps SAML attribute names to user field templates using mustache-style {{field}} syntax. Available fields: email, username, first_name, last_name, groups",
                      example: %{
                        "email" => "{{email}}",
                        "displayName" => "{{first_name}} {{last_name}}",
                        "groups" => "{{groups}}"
                      }
                    }
                  },
                  required: ["name", "entity_id", "acs_url"]
                }
              },
              required: ["saml_provider"]
            },
            examples: %{
              basic: %{
                summary: "Basic SAML provider with default mapping",
                value: %{
                  saml_provider: %{
                    name: "Salesforce Production",
                    entity_id: "https://acme.salesforce.com",
                    acs_url: "https://acme.salesforce.com/saml/acs",
                    attribute_mapping: %{
                      "email" => "{{email}}",
                      "firstName" => "{{first_name}}",
                      "lastName" => "{{last_name}}",
                      "displayName" => "{{first_name}} {{last_name}}",
                      "groups" => "{{groups}}"
                    }
                  }
                }
              },
              advanced: %{
                summary: "Advanced SAML provider with custom templates",
                value: %{
                  saml_provider: %{
                    name: "Enterprise Portal",
                    entity_id: "https://portal.example.com/saml",
                    acs_url: "https://portal.example.com/saml/consume",
                    slo_url: "https://portal.example.com/saml/logout",
                    attribute_mapping: %{
                      "email" => "{{email}}",
                      "username" => "{{username}}",
                      "fullName" => "{{last_name}}, {{first_name}}",
                      "memberOf" => "{{groups}}"
                    }
                  }
                }
              }
            }
          }
        }
      },
      responses: %{
        "201" => %{
          description: "SAML provider created successfully",
          content: %{
            "application/vnd.authify.v1+json" => %{
              schema: %{
                type: "object",
                properties: %{
                  data: %{type: "object"},
                  links: %{type: "object"}
                }
              }
            }
          }
        },
        "401" => %{"$ref" => "#/components/responses/Unauthorized"},
        "403" => %{"$ref" => "#/components/responses/Forbidden"},
        "422" => %{"$ref" => "#/components/responses/ValidationError"}
      }
    }
  end

  defp build_get_saml_provider do
    %{
      tags: ["SAML Providers"],
      summary: "Get SAML provider",
      description:
        "Retrieve a specific SAML service provider's configuration. Requires `saml:read` scope.",
      security: [
        %{"OAuth2" => ["saml:read"]},
        %{"BearerAuth" => []},
        %{"SessionAuth" => []}
      ],
      parameters: [
        %{
          name: "id",
          in: "path",
          required: true,
          description: "SAML Provider ID",
          schema: %{type: "string"}
        }
      ],
      responses: %{
        "200" => %{
          description: "SAML provider retrieved successfully",
          content: %{
            "application/vnd.authify.v1+json" => %{
              schema: %{
                type: "object",
                properties: %{
                  data: %{
                    type: "object",
                    properties: %{
                      id: %{type: "string"},
                      type: %{type: "string", example: "service_provider"},
                      attributes: %{
                        type: "object",
                        properties: %{
                          name: %{type: "string"},
                          entity_id: %{type: "string"},
                          acs_url: %{type: "string", format: "uri"},
                          slo_url: %{type: "string", format: "uri", nullable: true},
                          attribute_mapping: %{
                            type: "object",
                            description:
                              "SAML attribute mapping with mustache-style templates. Keys are SAML attribute names, values are templates using {{field}} syntax.",
                            example: %{
                              "email" => "{{email}}",
                              "displayName" => "{{first_name}} {{last_name}}",
                              "username" => "{{username}}",
                              "groups" => "{{groups}}"
                            }
                          },
                          inserted_at: %{type: "string", format: "date-time"},
                          updated_at: %{type: "string", format: "date-time"}
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
  end

  defp build_update_saml_provider do
    %{
      tags: ["SAML Providers"],
      summary: "Update SAML provider",
      description: "Update a SAML service provider's configuration. Requires `saml:write` scope.",
      security: [
        %{"OAuth2" => ["saml:write"]},
        %{"BearerAuth" => []},
        %{"SessionAuth" => []}
      ],
      parameters: [
        %{
          name: "id",
          in: "path",
          required: true,
          description: "SAML Provider ID",
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
                saml_provider: %{
                  type: "object",
                  properties: %{
                    name: %{type: "string"},
                    entity_id: %{type: "string", format: "uri"},
                    acs_url: %{type: "string", format: "uri"},
                    slo_url: %{type: "string", format: "uri", nullable: true},
                    attribute_mapping: %{
                      type: "object",
                      description:
                        "Update SAML attribute mapping. Use mustache-style {{field_name}} syntax for templating. Available fields: email, username, first_name, last_name, groups.",
                      example: %{
                        "mail" => "{{email}}",
                        "cn" => "{{first_name}} {{last_name}}",
                        "memberOf" => "{{groups}}"
                      }
                    }
                  }
                }
              },
              required: ["saml_provider"]
            }
          }
        }
      },
      responses: %{
        "200" => %{
          description: "SAML provider updated successfully",
          content: %{
            "application/vnd.authify.v1+json" => %{
              schema: %{
                type: "object",
                properties: %{
                  data: %{type: "object"},
                  links: %{type: "object"}
                }
              }
            }
          }
        },
        "401" => %{"$ref" => "#/components/responses/Unauthorized"},
        "403" => %{"$ref" => "#/components/responses/Forbidden"},
        "404" => %{"$ref" => "#/components/responses/NotFound"},
        "422" => %{"$ref" => "#/components/responses/ValidationError"}
      }
    }
  end

  defp build_delete_saml_provider do
    %{
      tags: ["SAML Providers"],
      summary: "Delete SAML provider",
      description:
        "Delete a SAML service provider from the organization. Requires `saml:write` scope.",
      security: [
        %{"OAuth2" => ["saml:write"]},
        %{"BearerAuth" => []},
        %{"SessionAuth" => []}
      ],
      parameters: [
        %{
          name: "id",
          in: "path",
          required: true,
          description: "SAML Provider ID",
          schema: %{type: "string"}
        }
      ],
      responses: %{
        "204" => %{description: "SAML provider deleted successfully"},
        "401" => %{"$ref" => "#/components/responses/Unauthorized"},
        "403" => %{"$ref" => "#/components/responses/Forbidden"},
        "404" => %{"$ref" => "#/components/responses/NotFound"}
      }
    }
  end
end
