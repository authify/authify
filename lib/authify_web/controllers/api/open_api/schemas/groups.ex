defmodule AuthifyWeb.API.OpenAPI.Schemas.Groups do
  @moduledoc """
  OpenAPI schema definitions for groups.
  """

  @doc """
  Returns the group-related schema definitions.
  """
  def build do
    %{
      "GroupAttributes" => group_attributes(),
      "GroupResource" => group_resource(),
      "GroupResponse" => group_response(),
      "GroupsCollectionResponse" => groups_collection_response(),
      "GroupCreateRequest" => group_create_request(),
      "GroupUpdateRequest" => group_update_request(),
      "GroupMembersResponse" => group_members_response()
    }
  end

  @doc """
  Example groups list response data.
  """
  def groups_list_example do
    %{
      data: [
        %{
          id: "201",
          type: "group",
          attributes: %{
            name: "Engineering",
            description: "Engineering team members",
            is_active: true,
            organization_id: 123,
            inserted_at: "2024-01-01T00:00:00Z",
            updated_at: "2024-01-01T00:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/groups/201"
          }
        },
        %{
          id: "202",
          type: "group",
          attributes: %{
            name: "Marketing",
            description: "Marketing department",
            is_active: true,
            organization_id: 123,
            inserted_at: "2024-02-15T10:00:00Z",
            updated_at: "2024-02-15T10:00:00Z"
          },
          links: %{
            self: "/acme-corp/api/groups/202"
          }
        }
      ],
      links: %{
        self: "/acme-corp/api/groups?page=1&per_page=25",
        first: "/acme-corp/api/groups?page=1&per_page=25"
      },
      meta: %{
        total: 2,
        page: 1,
        per_page: 25
      }
    }
  end

  @doc """
  Example group response data.
  """
  def group_example do
    %{
      data: %{
        id: "201",
        type: "group",
        attributes: %{
          name: "Engineering",
          description: "Engineering team members",
          is_active: true,
          organization_id: 123,
          inserted_at: "2024-01-01T00:00:00Z",
          updated_at: "2024-01-01T00:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/groups/201"
        }
      },
      links: %{
        self: "/acme-corp/api/groups/201"
      }
    }
  end

  @doc """
  Example group members response data.
  """
  def group_members_example do
    %{
      data: %{
        id: "201",
        type: "group_members",
        attributes: %{
          users: [
            %{
              id: 456,
              email: "john@acme.com",
              first_name: "John",
              last_name: "Doe"
            }
          ],
          applications: [
            %{
              id: 101,
              application_id: 789,
              application_type: "oauth_application"
            },
            %{
              id: 102,
              application_id: 790,
              application_type: "saml_provider"
            }
          ]
        }
      }
    }
  end

  defp group_attributes do
    %{
      type: "object",
      properties: %{
        name: %{type: "string", description: "Group name"},
        description: %{
          type: "string",
          nullable: true,
          description: "Group description"
        },
        is_active: %{
          type: "boolean",
          description: "Whether the group is active"
        },
        organization_id: %{type: "integer", description: "Organization ID"},
        inserted_at: %{type: "string", format: "date-time", description: "Creation timestamp"},
        updated_at: %{type: "string", format: "date-time", description: "Last update timestamp"}
      }
    }
  end

  defp group_resource do
    %{
      type: "object",
      properties: %{
        id: %{type: "string", description: "Group ID"},
        type: %{type: "string", enum: ["group"], description: "Resource type"},
        attributes: %{"$ref" => "#/components/schemas/GroupAttributes"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["id", "type", "attributes", "links"]
    }
  end

  defp group_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/GroupResource"},
        links: %{"$ref" => "#/components/schemas/ResourceLinks"}
      },
      required: ["data", "links"]
    }
  end

  defp groups_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{type: "array", items: %{"$ref" => "#/components/schemas/GroupResource"}},
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp group_create_request do
    %{
      type: "object",
      properties: %{
        group: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255, description: "Group name"},
            description: %{
              type: "string",
              maxLength: 1000,
              nullable: true,
              description: "Group description"
            },
            is_active: %{
              type: "boolean",
              default: true,
              description: "Whether the group should be active"
            }
          },
          required: ["name"]
        }
      },
      required: ["group"]
    }
  end

  defp group_update_request do
    %{
      type: "object",
      properties: %{
        group: %{
          type: "object",
          properties: %{
            name: %{type: "string", minLength: 1, maxLength: 255, description: "Group name"},
            description: %{
              type: "string",
              maxLength: 1000,
              nullable: true,
              description: "Group description"
            },
            is_active: %{type: "boolean", description: "Whether the group is active"}
          }
        }
      },
      required: ["group"]
    }
  end

  defp group_members_response do
    %{
      type: "object",
      properties: %{
        data: %{
          type: "object",
          properties: %{
            id: %{type: "string", description: "Group ID"},
            type: %{type: "string", enum: ["group_members"], description: "Resource type"},
            attributes: %{
              type: "object",
              properties: %{
                users: %{
                  type: "array",
                  description: "Users in this group",
                  items: %{
                    type: "object",
                    properties: %{
                      id: %{type: "integer"},
                      email: %{type: "string"},
                      first_name: %{type: "string"},
                      last_name: %{type: "string"}
                    }
                  }
                },
                applications: %{
                  type: "array",
                  description: "Applications associated with this group",
                  items: %{
                    type: "object",
                    properties: %{
                      id: %{type: "integer", description: "Group application membership ID"},
                      application_id: %{type: "integer", description: "Application ID"},
                      application_type: %{
                        type: "string",
                        enum: ["oauth_application", "saml_provider"],
                        description: "Type of application"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  end
end
