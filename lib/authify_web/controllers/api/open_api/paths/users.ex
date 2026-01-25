defmodule AuthifyWeb.API.OpenAPI.Paths.Users do
  @moduledoc """
  OpenAPI path definitions for user endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Users

  @doc """
  Returns the user endpoint definitions.
  """
  def build do
    %{
      "/{org_slug}/api/users" => users_collection(),
      "/{org_slug}/api/users/{id}" => user_resource(),
      "/{org_slug}/api/users/{id}/role" => user_role(),
      "/{org_slug}/api/users/{id}/mfa" => user_mfa_status(),
      "/{org_slug}/api/users/{id}/mfa/unlock" => user_mfa_unlock(),
      "/{org_slug}/api/users/{id}/mfa/reset" => user_mfa_reset()
    }
  end

  defp users_collection do
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
                example: Users.users_list_example()
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

  defp user_resource do
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

  defp user_role do
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

  defp user_mfa_status do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Users"],
        summary: "Get user MFA status",
        description:
          "Retrieve the MFA (Multi-Factor Authentication) status for a specific user, including TOTP status, WebAuthn credentials count, backup codes count, trusted devices count, and lockout information",
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
            description: "MFA status retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{
                      type: "object",
                      properties: %{
                        id: %{type: "string", description: "User ID"},
                        type: %{type: "string", enum: ["mfa_status"]},
                        attributes: %{
                          type: "object",
                          properties: %{
                            totp_enabled: %{
                              type: "boolean",
                              description: "Whether TOTP is enabled"
                            },
                            totp_enabled_at: %{
                              type: "string",
                              format: "date-time",
                              nullable: true,
                              description: "When TOTP was enabled (ISO 8601)"
                            },
                            backup_codes_count: %{
                              type: "integer",
                              description: "Number of unused backup codes"
                            },
                            trusted_devices_count: %{
                              type: "integer",
                              description: "Number of trusted devices"
                            },
                            webauthn_credentials_count: %{
                              type: "integer",
                              description:
                                "Number of registered WebAuthn credentials (security keys, passkeys)"
                            },
                            lockout: %{
                              type: "object",
                              nullable: true,
                              properties: %{
                                locked: %{type: "boolean"},
                                locked_until: %{type: "string", format: "date-time"}
                              },
                              description: "Lockout status (null if not locked out)"
                            }
                          }
                        }
                      }
                    },
                    links: %{
                      type: "object",
                      properties: %{
                        self: %{type: "string", format: "uri"}
                      }
                    }
                  }
                },
                example: %{
                  data: %{
                    id: "12345",
                    type: "mfa_status",
                    attributes: %{
                      totp_enabled: true,
                      totp_enabled_at: "2026-01-01T12:00:00Z",
                      backup_codes_count: 8,
                      trusted_devices_count: 2,
                      webauthn_credentials_count: 1,
                      lockout: nil
                    }
                  },
                  links: %{
                    self: "https://authify.example.com/acme/api/users/12345/mfa"
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

  defp user_mfa_unlock do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["Users"],
        summary: "Unlock user MFA",
        description:
          "Unlock a user who is locked out from MFA due to too many failed verification attempts. This clears the lockout and allows the user to attempt MFA verification again.",
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
          "200" => %{
            description: "User MFA lockout removed successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{
                      type: "object",
                      properties: %{
                        id: %{type: "string", description: "User ID"},
                        type: %{type: "string", enum: ["mfa_unlock"]},
                        attributes: %{
                          type: "object",
                          properties: %{
                            message: %{type: "string"}
                          }
                        }
                      }
                    },
                    links: %{
                      type: "object",
                      properties: %{
                        self: %{type: "string", format: "uri"},
                        user: %{type: "string", format: "uri"}
                      }
                    }
                  }
                },
                example: %{
                  data: %{
                    id: "12345",
                    type: "mfa_unlock",
                    attributes: %{
                      message: "User MFA lockout has been removed"
                    }
                  },
                  links: %{
                    self: "https://authify.example.com/acme/api/users/12345/mfa",
                    user: "https://authify.example.com/acme/api/users/12345"
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

  defp user_mfa_reset do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["Users"],
        summary: "Reset user TOTP",
        description:
          "Reset a user's TOTP configuration. This disables TOTP, revokes all trusted devices, clears backup codes, and removes any lockouts. Note: This does not revoke WebAuthn credentials - those must be managed separately through the WebAuthn credential management endpoints. The user will need to set up TOTP again from scratch.",
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
          "200" => %{
            description: "User MFA reset successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{
                  type: "object",
                  properties: %{
                    data: %{
                      type: "object",
                      properties: %{
                        id: %{type: "string", description: "User ID"},
                        type: %{type: "string", enum: ["mfa_reset"]},
                        attributes: %{
                          type: "object",
                          properties: %{
                            message: %{type: "string"}
                          }
                        }
                      }
                    },
                    links: %{
                      type: "object",
                      properties: %{
                        self: %{type: "string", format: "uri"},
                        user: %{type: "string", format: "uri"}
                      }
                    }
                  }
                },
                example: %{
                  data: %{
                    id: "12345",
                    type: "mfa_reset",
                    attributes: %{
                      message: "User MFA has been reset. They will need to set it up again."
                    }
                  },
                  links: %{
                    self: "https://authify.example.com/acme/api/users/12345/mfa",
                    user: "https://authify.example.com/acme/api/users/12345"
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
