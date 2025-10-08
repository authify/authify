defmodule Authify.SAML do
  @moduledoc """
  The SAML context for handling SAML Identity Provider functionality.
  """

  import Ecto.Query, warn: false
  alias Authify.Repo

  alias Authify.SAML.{ServiceProvider, Session, Certificate}
  alias Authify.Accounts.{User, Organization}

  @doc """
  Returns the list of service providers for an organization.
  """
  def list_service_providers(%Organization{id: org_id}) do
    ServiceProvider
    |> where([sp], sp.organization_id == ^org_id)
    |> order_by([sp], desc: sp.inserted_at)
    |> Repo.all()
  end

  @doc """
  Returns a filtered and sorted list of SAML service providers for an organization.

  ## Options
    * `:sort` - Field to sort by (atom, e.g., :entity_id, :inserted_at)
    * `:order` - Sort order (:asc or :desc, defaults to :desc)
    * `:search` - Text search across entity_id and acs_url fields
    * `:status` - Filter by active status (boolean or "all")

  ## Examples

      iex> list_service_providers_filtered(org, sort: :entity_id, order: :asc, search: "app")
      [%ServiceProvider{}, ...]
  """
  def list_service_providers_filtered(%Organization{id: org_id}, opts \\ []) do
    query =
      from(sp in ServiceProvider,
        where: sp.organization_id == ^org_id
      )

    query
    |> apply_saml_provider_filters(opts)
    |> apply_saml_provider_search(opts[:search])
    |> apply_saml_provider_sorting(opts[:sort], opts[:order])
    |> Repo.all()
  end

  defp apply_saml_provider_filters(query, opts) do
    maybe_filter_saml_provider_by_status(query, opts[:status])
  end

  defp maybe_filter_saml_provider_by_status(query, nil),
    do: where(query, [sp], sp.is_active == true)

  defp maybe_filter_saml_provider_by_status(query, ""),
    do: where(query, [sp], sp.is_active == true)

  defp maybe_filter_saml_provider_by_status(query, "all"), do: query

  defp maybe_filter_saml_provider_by_status(query, true),
    do: where(query, [sp], sp.is_active == true)

  defp maybe_filter_saml_provider_by_status(query, "true"),
    do: where(query, [sp], sp.is_active == true)

  defp maybe_filter_saml_provider_by_status(query, false),
    do: where(query, [sp], sp.is_active == false)

  defp maybe_filter_saml_provider_by_status(query, "false"),
    do: where(query, [sp], sp.is_active == false)

  defp maybe_filter_saml_provider_by_status(query, _),
    do: where(query, [sp], sp.is_active == true)

  defp apply_saml_provider_search(query, nil), do: query
  defp apply_saml_provider_search(query, ""), do: query

  defp apply_saml_provider_search(query, search_term) when is_binary(search_term) do
    search_pattern = "%#{search_term}%"

    where(
      query,
      [sp],
      like(sp.entity_id, ^search_pattern) or like(sp.acs_url, ^search_pattern)
    )
  end

  defp apply_saml_provider_sorting(query, nil, _),
    do: order_by(query, [sp], desc: sp.inserted_at)

  defp apply_saml_provider_sorting(query, "", _), do: order_by(query, [sp], desc: sp.inserted_at)

  defp apply_saml_provider_sorting(query, sort_field, order)
       when sort_field in [:entity_id, :acs_url, :inserted_at, :updated_at] do
    order_atom = if order == :asc or order == "asc", do: :asc, else: :desc
    order_by(query, [sp], ^[{order_atom, sort_field}])
  end

  defp apply_saml_provider_sorting(query, _sort_field, _order),
    do: order_by(query, [sp], desc: sp.inserted_at)

  @doc """
  Returns a paginated list of service providers for an organization.
  """
  def list_service_providers_paginated(%Organization{id: org_id}, opts \\ []) do
    page = Keyword.get(opts, :page, 1)
    per_page = Keyword.get(opts, :per_page, 25)
    offset = (page - 1) * per_page

    # Get total count
    total =
      ServiceProvider
      |> where([sp], sp.organization_id == ^org_id)
      |> Repo.aggregate(:count, :id)

    # Get paginated results
    service_providers =
      ServiceProvider
      |> where([sp], sp.organization_id == ^org_id)
      |> order_by([sp], desc: sp.inserted_at)
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    {service_providers, total}
  end

  @doc """
  Gets a single service provider by ID within an organization.
  """
  def get_service_provider!(id, %Organization{id: org_id}) do
    ServiceProvider
    |> where([sp], sp.id == ^id and sp.organization_id == ^org_id)
    |> Repo.one!()
  end

  @doc """
  Gets a single service provider by entity ID (not organization-scoped).

  WARNING: This function does not validate organization membership.
  Use `get_service_provider_by_entity_id/2` when you have an organization context.
  """
  def get_service_provider_by_entity_id(entity_id) do
    ServiceProvider
    |> where([sp], sp.entity_id == ^entity_id and sp.is_active == true)
    |> Repo.one()
  end

  @doc """
  Gets a single service provider by entity ID within a specific organization.

  This is the secure version that validates the service provider belongs to the organization.
  """
  def get_service_provider_by_entity_id(entity_id, %Organization{id: org_id}) do
    ServiceProvider
    |> where(
      [sp],
      sp.entity_id == ^entity_id and sp.organization_id == ^org_id and sp.is_active == true
    )
    |> Repo.one()
  end

  @doc """
  Creates a service provider.
  """
  def create_service_provider(attrs \\ %{}) do
    %ServiceProvider{}
    |> ServiceProvider.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a service provider.
  """
  def update_service_provider(%ServiceProvider{} = service_provider, attrs) do
    service_provider
    |> ServiceProvider.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a service provider.
  """
  def delete_service_provider(%ServiceProvider{} = service_provider) do
    Repo.delete(service_provider)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking service provider changes.
  """
  def change_service_provider(%ServiceProvider{} = service_provider, attrs \\ %{}) do
    ServiceProvider.changeset(service_provider, attrs)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking service provider form changes without validation.
  """
  def change_service_provider_form(%ServiceProvider{} = service_provider, attrs \\ %{}) do
    ServiceProvider.form_changeset(service_provider, attrs)
  end

  @doc """
  Creates a SAML session.
  """
  def create_session(attrs \\ %{}) do
    %Session{}
    |> Session.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets a SAML session by session ID.
  """
  def get_session(session_id) do
    Session
    |> where([s], s.session_id == ^session_id)
    |> preload([:user, :service_provider])
    |> Repo.one()
  end

  @doc """
  Updates a SAML session with new attributes.
  """
  def update_session(%Session{} = session, attrs) do
    session
    |> Session.changeset(attrs)
    |> Repo.update()
    |> case do
      {:ok, updated_session} ->
        {:ok, Repo.preload(updated_session, [:user, :service_provider])}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Deletes expired SAML sessions.
  """
  def cleanup_expired_sessions do
    now = DateTime.utc_now()

    expired_sessions_query =
      from(s in Session,
        where: s.expires_at < ^now
      )

    expired_sessions_deleted = Repo.delete_all(expired_sessions_query)

    {:ok, %{saml_sessions: expired_sessions_deleted}}
  end

  @doc """
  Gets all active SAML sessions for a user.
  """
  def get_active_sessions_for_user(%User{id: user_id}) do
    now = DateTime.utc_now()

    Session
    |> where([s], s.user_id == ^user_id and s.expires_at > ^now)
    |> preload([:service_provider])
    |> Repo.all()
  end

  @doc """
  Returns all SAML sessions for a user (including expired ones).
  """
  def list_user_sessions(%User{id: user_id}) do
    Session
    |> where([s], s.user_id == ^user_id)
    |> preload([:service_provider])
    |> order_by([s], desc: s.inserted_at)
    |> Repo.all()
  end

  @doc """
  Terminates a SAML session.
  """
  def terminate_session(%Session{} = session) do
    # Mark session as expired immediately
    session
    |> Ecto.Changeset.change(%{expires_at: DateTime.utc_now() |> DateTime.truncate(:second)})
    |> Repo.update()
  end

  @doc """
  Terminates all SAML sessions for a user.
  """
  def terminate_all_sessions_for_user(%User{id: user_id}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    from(s in Session,
      where: s.user_id == ^user_id and s.expires_at > ^now
    )
    |> Repo.update_all(set: [expires_at: now, updated_at: now])
  end

  @doc """
  Parses a SAML logout request.
  """
  def parse_saml_logout_request(saml_request_data) do
    Authify.SAML.XML.parse_logout_request(saml_request_data)
  end

  @doc """
  Generates a SAML logout response.
  """
  def generate_saml_logout_response(logout_request, %ServiceProvider{} = sp) do
    Authify.SAML.XML.generate_logout_response(logout_request, sp)
  end

  @doc """
  Generates a SAML logout request (for IdP-initiated logout).
  """
  def generate_saml_logout_request(%Session{} = session, %ServiceProvider{} = sp) do
    Authify.SAML.XML.generate_logout_request(session, sp)
  end

  @doc """
  Returns the list of certificates for an organization.
  """
  def list_certificates(%Organization{id: org_id}) do
    Certificate
    |> where([c], c.organization_id == ^org_id)
    |> order_by([c], desc: c.inserted_at)
    |> Repo.all()
  end

  @doc """
  Gets an active certificate for a specific purpose.
  """
  def get_active_certificate(%Organization{id: org_id}, purpose)
      when purpose in ["signing", "encryption"] do
    Certificate
    |> where([c], c.organization_id == ^org_id and c.purpose == ^purpose and c.is_active == true)
    |> where([c], c.expires_at > ^DateTime.utc_now())
    |> order_by([c], desc: c.inserted_at)
    |> limit(1)
    |> Repo.one()
  end

  @doc """
  Creates a certificate.
  """
  def create_certificate(attrs \\ %{}) do
    %Certificate{}
    |> Certificate.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a certificate.
  """
  def update_certificate(%Certificate{} = certificate, attrs) do
    certificate
    |> Certificate.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a certificate.
  """
  def delete_certificate(%Certificate{} = certificate) do
    Repo.delete(certificate)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking certificate changes.
  """
  def change_certificate(%Certificate{} = certificate, attrs \\ %{}) do
    Certificate.changeset(certificate, attrs)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking certificate form changes without validation.
  """
  def change_certificate_form(%Certificate{} = certificate, attrs \\ %{}) do
    Certificate.form_changeset(certificate, attrs)
  end

  @doc """
  Validates a SAML request and extracts key information.
  """
  def parse_saml_request(saml_request_data) do
    Authify.SAML.XML.parse_authn_request(saml_request_data)
  end

  @doc """
  Generates a SAML response with assertion.
  """
  def generate_saml_response(%Session{} = session, %ServiceProvider{} = sp, %User{} = user) do
    Authify.SAML.XML.generate_saml_response(session, sp, user)
  end

  @doc """
  Generates SAML IdP metadata XML.
  """
  def generate_metadata(organization) do
    Authify.SAML.XML.generate_metadata(organization)
  end
end
