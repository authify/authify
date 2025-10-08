defmodule AuthifyWeb.API.CertificatesController do
  use AuthifyWeb.API.BaseController

  alias Authify.Accounts

  @doc """
  GET /{org_slug}/api/certificates

  List certificates in the current organization with pagination.
  Requires certificates:read scope.
  """
  def index(conn, params) do
    with :ok <- ensure_scope(conn, "certificates:read") do
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
    else
      {:error, response} -> response
    end
  end

  @doc """
  GET /{org_slug}/api/certificates/:id

  Get a specific certificate by ID.
  Requires certificates:read scope.
  """
  def show(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "certificates:read") do
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
    else
      {:error, response} -> response
    end
  end

  @doc """
  POST /{org_slug}/api/certificates

  Create a new certificate in the current organization.
  Requires certificates:write scope.
  """
  def create(conn, %{"certificate" => certificate_params}) do
    with :ok <- ensure_scope(conn, "certificates:write") do
      organization = conn.assigns.current_organization

      case certificate_params["generate_new"] do
        "true" ->
          # Generate a new certificate
          case Accounts.generate_saml_signing_certificate(organization, certificate_params) do
            {:ok, certificate} ->
              render_api_response(conn, certificate,
                resource_type: "certificate",
                exclude: [:private_key],
                status: :created
              )

            {:error, %Ecto.Changeset{} = changeset} ->
              render_validation_errors(conn, changeset)
          end

        _ ->
          # Manual certificate creation
          case Accounts.create_certificate(organization, certificate_params) do
            {:ok, certificate} ->
              render_api_response(conn, certificate,
                resource_type: "certificate",
                exclude: [:private_key],
                status: :created
              )

            {:error, %Ecto.Changeset{} = changeset} ->
              render_validation_errors(conn, changeset)
          end
      end
    else
      {:error, response} -> response
    end
  end

  def create(conn, _params) do
    with :ok <- ensure_scope(conn, "certificates:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include certificate parameters"
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  PUT /{org_slug}/api/certificates/:id

  Update a certificate.
  Requires certificates:write scope.
  """
  def update(conn, %{"id" => id, "certificate" => certificate_params}) do
    with :ok <- ensure_scope(conn, "certificates:write") do
      organization = conn.assigns.current_organization

      try do
        certificate = Accounts.get_certificate!(id, organization)

        case Accounts.update_certificate(certificate, certificate_params) do
          {:ok, updated_certificate} ->
            render_api_response(conn, updated_certificate,
              resource_type: "certificate",
              exclude: [:private_key]
            )

          {:error, %Ecto.Changeset{} = changeset} ->
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
    else
      {:error, response} -> response
    end
  end

  def update(conn, %{"id" => _id}) do
    with :ok <- ensure_scope(conn, "certificates:write") do
      render_error_response(
        conn,
        :bad_request,
        "invalid_request",
        "Request must include certificate parameters"
      )
    else
      {:error, response} -> response
    end
  end

  @doc """
  DELETE /{org_slug}/api/certificates/:id

  Delete a certificate from the organization.
  Requires certificates:write scope.
  """
  def delete(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "certificates:write") do
      organization = conn.assigns.current_organization

      try do
        certificate = Accounts.get_certificate!(id, organization)

        case Accounts.delete_certificate(certificate) do
          {:ok, _deleted_certificate} ->
            conn |> put_status(:no_content) |> json(%{})

          {:error, %Ecto.Changeset{} = changeset} ->
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
    else
      {:error, response} -> response
    end
  end

  @doc """
  PATCH /{org_slug}/api/certificates/:id/activate

  Activate a certificate.
  Requires certificates:write scope.
  """
  def activate(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "certificates:write") do
      organization = conn.assigns.current_organization

      try do
        certificate = Accounts.get_certificate!(id, organization)

        case Accounts.update_certificate(certificate, %{"is_active" => true}) do
          {:ok, updated_certificate} ->
            render_api_response(conn, updated_certificate,
              resource_type: "certificate",
              exclude: [:private_key]
            )

          {:error, %Ecto.Changeset{} = changeset} ->
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
    else
      {:error, response} -> response
    end
  end

  @doc """
  PATCH /{org_slug}/api/certificates/:id/deactivate

  Deactivate a certificate.
  Requires certificates:write scope.
  """
  def deactivate(conn, %{"id" => id}) do
    with :ok <- ensure_scope(conn, "certificates:write") do
      organization = conn.assigns.current_organization

      try do
        certificate = Accounts.get_certificate!(id, organization)

        case Accounts.update_certificate(certificate, %{"is_active" => false}) do
          {:ok, updated_certificate} ->
            render_api_response(conn, updated_certificate,
              resource_type: "certificate",
              exclude: [:private_key]
            )

          {:error, %Ecto.Changeset{} = changeset} ->
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
    else
      {:error, response} -> response
    end
  end

  @doc """
  GET /{org_slug}/api/certificates/:id/download/:type

  Download certificate or private key.
  Requires certificates:read scope.
  """
  def download(conn, %{"id" => id, "type" => type}) when type in ["certificate", "private_key"] do
    with :ok <- ensure_scope(conn, "certificates:read") do
      organization = conn.assigns.current_organization

      try do
        certificate = Accounts.get_certificate!(id, organization)

        {content, filename, content_type} =
          case type do
            "certificate" ->
              {certificate.certificate, "#{certificate.name}_certificate.pem",
               "application/x-pem-file"}

            "private_key" ->
              {certificate.private_key, "#{certificate.name}_private_key.pem",
               "application/x-pem-file"}
          end

        conn
        |> put_resp_content_type(content_type)
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
    else
      {:error, response} -> response
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
end
