defmodule Authify.OAuthFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `Authify.OAuth` context.
  """

  @doc """
  Generate an OAuth application.
  """
  def application_fixture(attrs \\ %{}) do
    # Convert to map if it's a keyword list
    attrs = if is_list(attrs), do: Enum.into(attrs, %{}), else: attrs

    organization =
      case Map.get(attrs, :organization) do
        nil -> Authify.AccountsFixtures.organization_fixture()
        org -> org
      end

    attrs =
      attrs
      |> Map.drop([:organization])
      |> Enum.into(%{
        name: "Test Application",
        description: "A test OAuth application",
        redirect_uris: "https://example.com/callback\nhttps://app.example.com/auth",
        scopes: "openid profile email",
        application_type: "oauth2_app",
        organization_id: organization.id
      })

    {:ok, application} = Authify.OAuth.create_application(attrs)

    # Load the organization relationship
    application
    |> Authify.Repo.preload(:organization)
  end

  @doc """
  Generate a Management API application.
  """
  def management_api_application_fixture(attrs \\ %{}) do
    # Convert to map if it's a keyword list
    attrs = if is_list(attrs), do: Enum.into(attrs, %{}), else: attrs

    organization =
      case Map.get(attrs, :organization) do
        nil -> Authify.AccountsFixtures.organization_fixture()
        org -> org
      end

    attrs =
      attrs
      |> Map.drop([:organization])
      |> Enum.into(%{
        name: "Test Management API Client",
        description: "A test Management API application",
        redirect_uris: "",
        scopes: Enum.join(Authify.Scopes.management_api_scopes(), " "),
        application_type: "management_api_app",
        organization_id: organization.id
      })

    {:ok, application} = Authify.OAuth.create_application(attrs)

    # Load the organization relationship
    application
    |> Authify.Repo.preload(:organization)
  end

  @doc """
  Generate an authorization code.
  """
  def authorization_code_fixture(attrs \\ %{}) do
    application = attrs[:application] || application_fixture()

    user =
      attrs[:user] ||
        Authify.AccountsFixtures.user_for_organization_fixture(application.organization)

    redirect_uri = attrs[:redirect_uri] || "https://example.com/callback"
    scopes = attrs[:scopes] || ["openid", "profile"]

    {:ok, auth_code} =
      Authify.OAuth.create_authorization_code(application, user, redirect_uri, scopes)

    auth_code
  end

  @doc """
  Generate an access token.
  """
  def access_token_fixture(attrs \\ %{}) do
    auth_code = attrs[:auth_code] || authorization_code_fixture()
    application = attrs[:application] || auth_code.application

    {:ok, access_token} = Authify.OAuth.exchange_authorization_code(auth_code, application)
    access_token
  end
end
