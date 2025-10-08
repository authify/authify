defmodule AuthifyWeb.CertificatesController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.Certificate

  def index(conn, _params) do
    organization = conn.assigns.current_organization
    certificates = Accounts.list_certificates(organization)

    render(conn, :index, certificates: certificates)
  end

  def show(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    render(conn, :show, certificate: certificate)
  end

  def new(conn, _params) do
    changeset = Accounts.change_certificate(%Certificate{})
    render(conn, :new, changeset: changeset)
  end

  def create(conn, %{"certificate" => certificate_params}) do
    organization = conn.assigns.current_organization

    case certificate_params["generate_new"] do
      "true" ->
        # Generate a new certificate
        case Accounts.generate_certificate(organization, certificate_params) do
          {:ok, certificate} ->
            conn
            |> put_flash(:info, "Certificate generated successfully.")
            |> redirect(
              to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{certificate.id}"
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            render(conn, :new, changeset: changeset)
        end

      _ ->
        # Manual certificate creation
        case Accounts.create_certificate(organization, certificate_params) do
          {:ok, certificate} ->
            conn
            |> put_flash(:info, "Certificate created successfully.")
            |> redirect(
              to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{certificate.id}"
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            render(conn, :new, changeset: changeset)
        end
    end
  end

  def edit(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)
    changeset = Accounts.change_certificate(certificate)

    render(conn, :edit, certificate: certificate, changeset: changeset)
  end

  def update(conn, %{"id" => id, "certificate" => certificate_params}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    case Accounts.update_certificate(certificate, certificate_params) do
      {:ok, certificate} ->
        conn
        |> put_flash(:info, "Certificate updated successfully.")
        |> redirect(
          to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{certificate.id}"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit, certificate: certificate, changeset: changeset)
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    {:ok, _certificate} = Accounts.delete_certificate(certificate)

    conn
    |> put_flash(:info, "Certificate deleted successfully.")
    |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates")
  end

  def download(conn, %{"id" => id, "type" => type}) when type in ["certificate", "private_key"] do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    # Check access permissions
    current_user = conn.assigns.current_user

    unless Certificate.accessible_by_user?(certificate, current_user, "admin") do
      conn
      |> put_flash(:error, "You don't have permission to download this certificate.")
      |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates")
      |> halt()
    end

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
  end

  def activate(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    case Accounts.update_certificate(certificate, %{"is_active" => true}) do
      {:ok, _certificate} ->
        conn
        |> put_flash(:info, "Certificate activated successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Failed to activate certificate.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")
    end
  end

  def deactivate(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    case Accounts.update_certificate(certificate, %{"is_active" => false}) do
      {:ok, _certificate} ->
        conn
        |> put_flash(:info, "Certificate deactivated successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Failed to deactivate certificate.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")
    end
  end
end
