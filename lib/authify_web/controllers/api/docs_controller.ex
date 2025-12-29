defmodule AuthifyWeb.API.DocsController do
  use AuthifyWeb, :controller

  alias AuthifyWeb.API.OpenAPI.{Components, Paths, Schemas, Spec}

  def openapi(conn, _params) do
    # Get the base URL from configuration or build from current request
    base_url = Spec.get_api_base_url(conn)

    # Generate the OpenAPI specification dynamically
    openapi_spec = %{
      openapi: "3.1.0",
      info: Spec.info(base_url),
      servers: Spec.servers(base_url),
      security: Spec.security(),
      tags: Spec.tags(),
      paths: build_paths(),
      components: build_components(base_url)
    }

    conn
    |> put_resp_content_type("application/json")
    |> json(openapi_spec)
  end

  defp build_paths do
    Paths.Organizations.build()
    |> Map.merge(Paths.Users.build())
    |> Map.merge(Paths.Invitations.build())
    |> Map.merge(Paths.Applications.build())
    |> Map.merge(Paths.Groups.build())
    |> Map.merge(Paths.Certificates.build())
    |> Map.merge(Paths.SamlProviders.build())
    |> Map.merge(Paths.AuditLogs.build())
    |> Map.merge(Paths.Profile.build())
  end

  defp build_components(base_url) do
    %{
      securitySchemes: Components.Security.build(base_url),
      parameters: Components.Parameters.build(),
      schemas: build_schemas(),
      responses: Components.Responses.build(base_url)
    }
  end

  defp build_schemas do
    Schemas.Common.build()
    |> Map.merge(Schemas.Organizations.build())
    |> Map.merge(Schemas.Users.build())
    |> Map.merge(Schemas.Invitations.build())
    |> Map.merge(Schemas.Applications.build())
    |> Map.merge(Schemas.Groups.build())
    |> Map.merge(Schemas.Certificates.build())
    |> Map.merge(Schemas.Profile.build())
  end
end
