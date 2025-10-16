defmodule AuthifyWeb.CertificatesController do
  use AuthifyWeb, :controller

  alias Authify.Accounts
  alias Authify.Accounts.Certificate
  alias AuthifyWeb.Helpers.AuditHelper

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
            AuditHelper.log_certificate_event(conn, :certificate_created, certificate,
              generated: true,
              extra_metadata: %{source: "web"}
            )

            conn
            |> put_flash(:info, "Certificate generated successfully.")
            |> redirect(
              to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{certificate.id}"
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            AuditHelper.log_certificate_failure(
              conn,
              :certificate_created,
              AuditHelper.changeset_errors(changeset),
              extra_metadata: %{
                source: "web",
                attempted_name: certificate_params["name"],
                usage: certificate_params["usage"],
                generated: true
              }
            )

            render(conn, :new, changeset: changeset)
        end

      _ ->
        # Manual certificate creation
        case Accounts.create_certificate(organization, certificate_params) do
          {:ok, certificate} ->
            AuditHelper.log_certificate_event(conn, :certificate_created, certificate,
              generated: false,
              extra_metadata: %{source: "web"}
            )

            conn
            |> put_flash(:info, "Certificate created successfully.")
            |> redirect(
              to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{certificate.id}"
            )

          {:error, %Ecto.Changeset{} = changeset} ->
            AuditHelper.log_certificate_failure(
              conn,
              :certificate_created,
              AuditHelper.changeset_errors(changeset),
              extra_metadata: %{
                source: "web",
                attempted_name: certificate_params["name"],
                usage: certificate_params["usage"],
                generated: false
              }
            )

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
      {:ok, updated_certificate} ->
        maybe_log_activation_change(conn, certificate, updated_certificate, certificate_params,
          source: "web"
        )

        conn
        |> put_flash(:info, "Certificate updated successfully.")
        |> redirect(
          to:
            ~p"/#{conn.assigns.current_organization.slug}/certificates/#{updated_certificate.id}"
        )

      {:error, %Ecto.Changeset{} = changeset} ->
        maybe_log_activation_failure(conn, certificate, certificate_params, changeset,
          source: "web"
        )

        render(conn, :edit, certificate: certificate, changeset: changeset)
    end
  end

  def delete(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    {:ok, _certificate} = Accounts.delete_certificate(certificate)

    AuditHelper.log_certificate_event(conn, :certificate_deleted, certificate,
      extra_metadata: %{source: "web"}
    )

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

    {content, filename} =
      case type do
        "certificate" ->
          {certificate.certificate, "#{sanitize_filename(certificate.name)}_certificate.pem"}

        "private_key" ->
          {certificate.private_key, "#{sanitize_filename(certificate.name)}_private_key.pem"}
      end

    conn
    |> put_resp_content_type("application/x-pem-file")
    |> put_resp_header("content-disposition", "attachment; filename=\"#{filename}\"")
    |> send_resp(200, content)
  end

  # Sanitize filename to prevent header injection
  defp sanitize_filename(name) do
    name
    |> String.replace(~r/[^\w\-\.]/, "_")
    |> String.slice(0, 200)
  end

  def activate(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    case Accounts.update_certificate(certificate, %{"is_active" => true}) do
      {:ok, updated_certificate} ->
        AuditHelper.log_certificate_event(conn, :certificate_activated, updated_certificate,
          previous_state: %{"is_active" => certificate.is_active},
          extra_metadata: %{source: "web"}
        )

        conn
        |> put_flash(:info, "Certificate activated successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")

      {:error, %Ecto.Changeset{} = changeset} ->
        AuditHelper.log_certificate_failure(
          conn,
          :certificate_activated,
          AuditHelper.changeset_errors(changeset),
          certificate: certificate,
          extra_metadata: %{source: "web"}
        )

        conn
        |> put_flash(:error, "Failed to activate certificate.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")
    end
  end

  def deactivate(conn, %{"id" => id}) do
    organization = conn.assigns.current_organization
    certificate = Accounts.get_certificate!(id, organization)

    case Accounts.update_certificate(certificate, %{"is_active" => false}) do
      {:ok, updated_certificate} ->
        AuditHelper.log_certificate_event(conn, :certificate_deactivated, updated_certificate,
          previous_state: %{"is_active" => certificate.is_active},
          extra_metadata: %{source: "web"}
        )

        conn
        |> put_flash(:info, "Certificate deactivated successfully.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")

      {:error, %Ecto.Changeset{} = changeset} ->
        AuditHelper.log_certificate_failure(
          conn,
          :certificate_deactivated,
          AuditHelper.changeset_errors(changeset),
          certificate: certificate,
          extra_metadata: %{source: "web"}
        )

        conn
        |> put_flash(:error, "Failed to deactivate certificate.")
        |> redirect(to: ~p"/#{conn.assigns.current_organization.slug}/certificates/#{id}")
    end
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
end
