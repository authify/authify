defmodule AuthifyWeb.API.SAMLProvidersController do
  use AuthifyWeb.API.BaseController

  alias Authify.SAML

  def index(conn, params) do
    organization = conn.assigns.current_organization

    page = String.to_integer(params["page"] || "1")
    per_page = String.to_integer(params["per_page"] || "25")

    {saml_providers, total} =
      SAML.list_service_providers_paginated(organization, page: page, per_page: per_page)

    page_info = %{
      page: page,
      per_page: per_page,
      total: total
    }

    render_collection_response(conn, saml_providers,
      resource_type: "service_provider",
      page_info: page_info
    )
  end

  def show(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    try do
      saml_provider = SAML.get_service_provider!(id, organization)
      render_api_response(conn, saml_provider, resource_type: "service_provider")
    rescue
      Ecto.NoResultsError ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "SAML provider not found in organization"
        )
    end
  end

  def create(conn, %{"saml_provider" => saml_provider_params}) do
    organization = conn.assigns.current_organization

    attrs = Map.put(saml_provider_params, "organization_id", organization.id)

    case SAML.create_service_provider(attrs) do
      {:ok, saml_provider} ->
        render_api_response(conn, saml_provider,
          resource_type: "service_provider",
          status: :created
        )

      {:error, changeset} ->
        render_validation_errors(conn, changeset)
    end
  end

  def update(conn, %{"id" => id, "saml_provider" => saml_provider_params}) do
    organization = conn.assigns.current_organization

    try do
      saml_provider = SAML.get_service_provider!(id, organization)

      case SAML.update_service_provider(saml_provider, saml_provider_params) do
        {:ok, updated_saml_provider} ->
          render_api_response(conn, updated_saml_provider, resource_type: "service_provider")

        {:error, changeset} ->
          render_validation_errors(conn, changeset)
      end
    rescue
      Ecto.NoResultsError ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "SAML provider not found in organization"
        )
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization

    try do
      saml_provider = SAML.get_service_provider!(id, organization)

      case SAML.delete_service_provider(saml_provider) do
        {:ok, _saml_provider} ->
          send_resp(conn, :no_content, "")

        {:error, changeset} ->
          render_validation_errors(conn, changeset)
      end
    rescue
      Ecto.NoResultsError ->
        render_error_response(
          conn,
          :not_found,
          "resource_not_found",
          "SAML provider not found in organization"
        )
    end
  end
end
