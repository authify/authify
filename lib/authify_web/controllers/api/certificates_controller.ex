defmodule AuthifyWeb.API.CertificatesController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts
  alias AuthifyWeb.Helpers.AuditHelper

  @doc """
  GET /{org_slug}/api/certificates

  List certificates in the current organization with pagination.
  Requires certificates:read scope.
  """
  def index(conn, params) do
    case ensure_scope(conn, "certificates:read") do
      :ok ->
        organization = conn.assigns.current_organization
        page = String.to_integer(params["page"] || "1")
        per_page = min(String.to_integer(params["per_page"] || "25"), 100)

        # Get all certificates (filtering by usage will be added later)
        certificates = Accounts.list_certificates(organization)

        # Apply pagination manually for now
        offset = (page - 1) * per_page

        paginated_certificates =
          certificates
          |> Enum.drop(offset)
          |> Enum.take(per_page)

        total_count = length(certificates)

        render_collection_response(conn, paginated_certificates,
          resource_type: "certificate",
          exclude: [:private_key],
          page_info: %{
            page: page,
            per_page: per_page,
            total: total_count
          }
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/certificates/:id

  Get a specific certificate by ID.
  Requires certificates:read scope.
  """
  def show(conn, %{"id" => id}) do
    case ensure_scope(conn, "certificates:read") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          certificate = Accounts.get_certificate!(id, organization)

          render_api_response(conn, certificate,
            resource_type: "certificate",
            exclude: [:private_key]
          )
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Certificate not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  POST /{org_slug}/api/certificates

  Create a new certificate in the current organization.
  Requires certificates:write scope.
  """
  def create(conn, %{"certificate" => certificate_params}) do
    case ensure_scope(conn, "certificates:write") do
      :ok ->
        organization = conn.assigns.current_organization

        case certificate_params["generate_new"] do
          "true" ->
            # Generate a new certificate
            case Accounts.generate_saml_signing_certificate(organization, certificate_params) do
              {:ok, certificate} ->
                AuditHelper.log_certificate_event(conn, :certificate_created, certificate,
                  generated: true,
                  extra_metadata: %{source: "api"}
                )

                render_api_response(conn, certificate,
                  resource_type: "certificate",
                  exclude: [:private_key],
                  status: :created
                )

              {:error, %Ecto.Changeset{} = changeset} ->
                AuditHelper.log_certificate_failure(
                  conn,
                  :certificate_created,
                  AuditHelper.changeset_errors(changeset),
                  extra_metadata: %{
                    source: "api",
                    attempted_name: certificate_params["name"],
                    usage: certificate_params["usage"],
                    generated: true
                  }
                )

                render_validation_errors(conn, changeset)
            end

          _ ->
            # Manual certificate creation
            case Accounts.create_certificate(organization, certificate_params) do
              {:ok, certificate} ->
                AuditHelper.log_certificate_event(conn, :certificate_created, certificate,
                  generated: false,
                  extra_metadata: %{source: "api"}
                )

                render_api_response(conn, certificate,
                  resource_type: "certificate",
                  exclude: [:private_key],
                  status: :created
                )

              {:error, %Ecto.Changeset{} = changeset} ->
                AuditHelper.log_certificate_failure(
                  conn,
                  :certificate_created,
                  AuditHelper.changeset_errors(changeset),
                  extra_metadata: %{
                    source: "api",
                    attempted_name: certificate_params["name"],
                    usage: certificate_params["usage"],
                    generated: false
                  }
                )

                render_validation_errors(conn, changeset)
            end
        end

      {:error, response} ->
        response
    end
  end

  def create(conn, _params) do
    case ensure_scope(conn, "certificates:write") do
      :ok ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "Request must include certificate parameters"
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  PUT /{org_slug}/api/certificates/:id

  Update a certificate.
  Requires certificates:write scope.
  """
  def update(conn, %{"id" => id, "certificate" => certificate_params}) do
    case ensure_scope(conn, "certificates:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          certificate = Accounts.get_certificate!(id, organization)

          case Accounts.update_certificate(certificate, certificate_params) do
            {:ok, updated_certificate} ->
              maybe_log_activation_change(
                conn,
                certificate,
                updated_certificate,
                certificate_params,
                source: "api"
              )

              render_api_response(conn, updated_certificate,
                resource_type: "certificate",
                exclude: [:private_key]
              )

            {:error, %Ecto.Changeset{} = changeset} ->
              maybe_log_activation_failure(conn, certificate, certificate_params, changeset,
                source: "api"
              )

              render_validation_errors(conn, changeset)
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Certificate not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  def update(conn, %{"id" => _id}) do
    case ensure_scope(conn, "certificates:write") do
      :ok ->
        render_error_response(
          conn,
          :bad_request,
          "invalid_request",
          "Request must include certificate parameters"
        )

      {:error, response} ->
        response
    end
  end

  @doc """
  DELETE /{org_slug}/api/certificates/:id

  Delete a certificate from the organization.
  Requires certificates:write scope.
  """
  def delete(conn, %{"id" => id}) do
    case ensure_scope(conn, "certificates:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          certificate = Accounts.get_certificate!(id, organization)

          case Accounts.delete_certificate(certificate) do
            {:ok, _deleted_certificate} ->
              AuditHelper.log_certificate_event(conn, :certificate_deleted, certificate,
                extra_metadata: %{source: "api"}
              )

              conn |> put_status(:no_content) |> json(%{})

            {:error, %Ecto.Changeset{} = changeset} ->
              AuditHelper.log_certificate_failure(
                conn,
                :certificate_deleted,
                AuditHelper.changeset_errors(changeset),
                certificate: certificate,
                extra_metadata: %{source: "api"}
              )

              render_validation_errors(conn, changeset)
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Certificate not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  PATCH /{org_slug}/api/certificates/:id/activate

  Activate a certificate.
  Requires certificates:write scope.
  """
  def activate(conn, %{"id" => id}) do
    case ensure_scope(conn, "certificates:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          certificate = Accounts.get_certificate!(id, organization)

          case Accounts.update_certificate(certificate, %{"is_active" => true}) do
            {:ok, updated_certificate} ->
              AuditHelper.log_certificate_event(conn, :certificate_activated, updated_certificate,
                previous_state: %{"is_active" => certificate.is_active},
                extra_metadata: %{source: "api"}
              )

              render_api_response(conn, updated_certificate,
                resource_type: "certificate",
                exclude: [:private_key]
              )

            {:error, %Ecto.Changeset{} = changeset} ->
              AuditHelper.log_certificate_failure(
                conn,
                :certificate_activated,
                AuditHelper.changeset_errors(changeset),
                certificate: certificate,
                extra_metadata: %{source: "api"}
              )

              render_validation_errors(conn, changeset)
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Certificate not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  PATCH /{org_slug}/api/certificates/:id/deactivate

  Deactivate a certificate.
  Requires certificates:write scope.
  """
  def deactivate(conn, %{"id" => id}) do
    case ensure_scope(conn, "certificates:write") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          certificate = Accounts.get_certificate!(id, organization)

          case Accounts.update_certificate(certificate, %{"is_active" => false}) do
            {:ok, updated_certificate} ->
              AuditHelper.log_certificate_event(
                conn,
                :certificate_deactivated,
                updated_certificate,
                previous_state: %{"is_active" => certificate.is_active},
                extra_metadata: %{source: "api"}
              )

              render_api_response(conn, updated_certificate,
                resource_type: "certificate",
                exclude: [:private_key]
              )

            {:error, %Ecto.Changeset{} = changeset} ->
              AuditHelper.log_certificate_failure(
                conn,
                :certificate_deactivated,
                AuditHelper.changeset_errors(changeset),
                certificate: certificate,
                extra_metadata: %{source: "api"}
              )

              render_validation_errors(conn, changeset)
          end
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Certificate not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  @doc """
  GET /{org_slug}/api/certificates/:id/download/:type

  Download certificate or private key.
  Requires certificates:read scope.
  """
  def download(conn, %{"id" => id, "type" => type}) when type in ["certificate", "private_key"] do
    case ensure_scope(conn, "certificates:read") do
      :ok ->
        organization = conn.assigns.current_organization

        try do
          certificate = Accounts.get_certificate!(id, organization)

          {content, filename} =
            case type do
              "certificate" ->
                {certificate.certificate,
                 "#{sanitize_filename(certificate.name)}_certificate.pem"}

              "private_key" ->
                {certificate.private_key,
                 "#{sanitize_filename(certificate.name)}_private_key.pem"}
            end

          conn
          |> put_resp_content_type("application/x-pem-file")
          |> put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
          |> send_resp(200, content)
        rescue
          Ecto.NoResultsError ->
            render_error_response(
              conn,
              :not_found,
              "resource_not_found",
              "Certificate not found in organization"
            )
        end

      {:error, response} ->
        response
    end
  end

  def download(conn, %{"id" => _id, "type" => type}) do
    render_error_response(
      conn,
      :bad_request,
      "invalid_request",
      "Invalid download type: #{type}. Must be 'certificate' or 'private_key'"
    )
  end

  defp maybe_log_activation_change(conn, original, updated, params, opts) do
    if updated.is_active != original.is_active do
      event_type =
        if updated.is_active, do: :certificate_activated, else: :certificate_deactivated

      attempted_state =
        case Map.fetch(params, "is_active") do
          {:ok, value} -> truthy?(value)
          :error -> updated.is_active
        end

      AuditHelper.log_certificate_event(conn, event_type, updated,
        previous_state: %{"is_active" => original.is_active},
        extra_metadata: %{source: opts[:source], attempted_state: attempted_state}
      )
    end
  end

  defp maybe_log_activation_failure(conn, certificate, params, changeset, opts) do
    case params do
      %{"is_active" => desired} ->
        event_type =
          if truthy?(desired), do: :certificate_activated, else: :certificate_deactivated

        AuditHelper.log_certificate_failure(
          conn,
          event_type,
          AuditHelper.changeset_errors(changeset),
          certificate: certificate,
          extra_metadata: %{source: opts[:source], attempted_state: truthy?(desired)}
        )

      _ ->
        :ok
    end
  end

  defp truthy?(value) when value in [true, "true", 1, "1", "on"], do: true
  defp truthy?(_value), do: false

  # Sanitize filename to prevent header injection
  defp sanitize_filename(name) do
    name
    |> String.replace(~r/[^\w\-\.]/, "_")
    |> String.slice(0, 200)
  end
end
