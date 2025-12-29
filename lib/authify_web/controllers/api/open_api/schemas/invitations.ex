defmodule AuthifyWeb.API.OpenAPI.Schemas.Invitations do
  @moduledoc """
  OpenAPI schema definitions for invitations.
  """

  @doc """
  Returns the invitation-related schema definitions.
  """
  def build do
    %{
      "InvitationAttributes" => invitation_attributes(),
      "InvitationResource" => invitation_resource(),
      "InvitationResponse" => invitation_response(),
      "InvitationsCollectionResponse" => invitations_collection_response(),
      "InvitationCreateRequest" => invitation_create_request(),
      "InvitationUpdateRequest" => invitation_update_request()
    }
  end

  @doc """
  Example invitations list response data.
  """
  def invitations_list_example do
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

  @doc """
  Example invitation create response data.
  """
  def invitation_create_example do
    %{
      data: %{
        id: "458",
        type: "invitation",
        attributes: %{
          email: "newuser@example.com",
          role: "user",
          expires_at: "2024-12-31T23:59:59Z",
          accepted_at: nil,
          created_at: "2024-01-20T15:00:00Z",
          updated_at: "2024-01-20T15:00:00Z"
        },
        links: %{
          self: "/acme-corp/api/invitations/458"
        }
      }
    }
  end

  defp invitation_attributes do
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

  defp invitation_resource do
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

  defp invitation_response do
    %{
      type: "object",
      properties: %{
        data: %{"$ref" => "#/components/schemas/InvitationResource"}
      },
      required: ["data"]
    }
  end

  defp invitations_collection_response do
    %{
      type: "object",
      properties: %{
        data: %{
          type: "array",
          items: %{"$ref" => "#/components/schemas/InvitationResource"}
        },
        links: %{"$ref" => "#/components/schemas/CollectionLinks"},
        meta: %{"$ref" => "#/components/schemas/PaginationMeta"}
      },
      required: ["data", "links", "meta"]
    }
  end

  defp invitation_create_request do
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

  defp invitation_update_request do
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
end
