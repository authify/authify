defmodule AuthifyWeb.API.OpenAPI.Paths.Groups do
  @moduledoc """
  OpenAPI path definitions for group endpoints.
  """

  alias AuthifyWeb.API.OpenAPI.Schemas.Groups

  @doc """
  Returns the group endpoint definitions.
  """
  def build do
    %{
      "/{org_slug}/api/groups" => groups_collection(),
      "/{org_slug}/api/groups/{id}" => group_resource(),
      "/{org_slug}/api/groups/{id}/members" => group_members(),
      "/{org_slug}/api/groups/{id}/users" => group_users(),
      "/{org_slug}/api/groups/{id}/users/{user_id}" => group_user_resource(),
      "/{org_slug}/api/groups/{id}/applications" => group_applications(),
      "/{org_slug}/api/groups/{id}/applications/{member_id}" => group_application_resource()
    }
  end

  defp groups_collection do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Groups"],
        summary: "List groups",
        description: "Get a paginated list of groups in the organization",
        security: [
          %{"OAuth2" => ["groups:read"]},
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
            name: "sort",
            in: "query",
            description: "Field to sort by",
            schema: %{
              type: "string",
              enum: ["name", "description", "is_active", "inserted_at", "updated_at"],
              default: "name"
            }
          },
          %{
            name: "order",
            in: "query",
            description: "Sort order",
            schema: %{type: "string", enum: ["asc", "desc"], default: "asc"}
          },
          %{
            name: "search",
            in: "query",
            description: "Search term to filter groups by name or description",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Groups retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/GroupsCollectionResponse"},
                example: Groups.groups_list_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"}
        }
      },
      post: %{
        tags: ["Groups"],
        summary: "Create group",
        description: "Create a new group in the organization",
        security: [
          %{"OAuth2" => ["groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/GroupCreateRequest"},
              example: %{
                group: %{
                  name: "Engineering Team",
                  description: "Software engineering team",
                  is_active: true
                }
              }
            }
          }
        },
        responses: %{
          "201" => %{
            description: "Group created successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/GroupResponse"},
                example: Groups.group_example()
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

  defp group_resource do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Groups"],
        summary: "Get group",
        description: "Retrieve a specific group's details",
        security: [
          %{"OAuth2" => ["groups:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Group retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/GroupResponse"},
                example: Groups.group_example()
              }
            }
          },
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      },
      put: %{
        tags: ["Groups"],
        summary: "Update group",
        description: "Update a group's information",
        security: [
          %{"OAuth2" => ["groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
            schema: %{type: "string"}
          }
        ],
        requestBody: %{
          required: true,
          content: %{
            "application/json" => %{
              schema: %{"$ref" => "#/components/schemas/GroupUpdateRequest"},
              example: %{
                group: %{
                  name: "Updated Engineering Team",
                  description: "Updated description",
                  is_active: true
                }
              }
            }
          }
        },
        responses: %{
          "200" => %{
            description: "Group updated successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/GroupResponse"},
                example: Groups.group_example()
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
        tags: ["Groups"],
        summary: "Delete group",
        description: "Delete a group from the organization",
        security: [
          %{"OAuth2" => ["groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Group deleted successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp group_members do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      get: %{
        tags: ["Groups"],
        summary: "Get group members",
        description: "Retrieve all members (users and applications) of a group",
        security: [
          %{"OAuth2" => ["groups:read"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "200" => %{
            description: "Group members retrieved successfully",
            content: %{
              "application/vnd.authify.v1+json" => %{
                schema: %{"$ref" => "#/components/schemas/GroupMembersResponse"},
                example: Groups.group_members_example()
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

  defp group_users do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["Groups"],
        summary: "Add user to group",
        description: "Add a user to a group",
        security: [
          %{"OAuth2" => ["groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
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
                  user_id: %{
                    type: "string",
                    description: "ID of the user to add to the group"
                  }
                },
                required: ["user_id"]
              },
              example: %{user_id: "123"}
            }
          }
        },
        responses: %{
          "204" => %{description: "User added to group successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp group_user_resource do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      delete: %{
        tags: ["Groups"],
        summary: "Remove user from group",
        description: "Remove a user from a group",
        security: [
          %{"OAuth2" => ["groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
            schema: %{type: "string"}
          },
          %{
            name: "user_id",
            in: "path",
            required: true,
            description: "User ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "User removed from group successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end

  defp group_applications do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      post: %{
        tags: ["Groups"],
        summary: "Add application to group",
        description: "Add an application to a group",
        security: [
          %{"OAuth2" => ["groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
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
                  application_id: %{
                    type: "string",
                    description: "ID of the application to add to the group"
                  },
                  application_type: %{
                    type: "string",
                    enum: ["oauth_client", "saml_provider"],
                    description: "Type of the application"
                  }
                },
                required: ["application_id", "application_type"]
              },
              example: %{application_id: "456", application_type: "oauth_client"}
            }
          }
        },
        responses: %{
          "204" => %{description: "Application added to group successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"},
          "422" => %{"$ref" => "#/components/responses/ValidationError"}
        }
      }
    }
  end

  defp group_application_resource do
    %{
      parameters: [
        %{"$ref" => "#/components/parameters/OrgSlug"},
        %{"$ref" => "#/components/parameters/AcceptHeader"}
      ],
      delete: %{
        tags: ["Groups"],
        summary: "Remove application from group",
        description: "Remove an application from a group",
        security: [
          %{"OAuth2" => ["groups:write"]},
          %{"BearerAuth" => []},
          %{"SessionAuth" => []}
        ],
        parameters: [
          %{
            name: "id",
            in: "path",
            required: true,
            description: "Group ID",
            schema: %{type: "string"}
          },
          %{
            name: "member_id",
            in: "path",
            required: true,
            description: "Group application member ID",
            schema: %{type: "string"}
          }
        ],
        responses: %{
          "204" => %{description: "Application removed from group successfully"},
          "401" => %{"$ref" => "#/components/responses/Unauthorized"},
          "403" => %{"$ref" => "#/components/responses/Forbidden"},
          "404" => %{"$ref" => "#/components/responses/NotFound"}
        }
      }
    }
  end
end
