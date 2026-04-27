defmodule AuthifyWeb.IntegrationCase do
  @moduledoc """
  Base case template for cross-protocol integration tests.

  Wires together all four protocol client simulators and provides a
  pre-created organization and admin user in every test context via
  `setup :setup_integration`.

  Each test receives: `%{conn: conn, org: org, admin: admin}`.
  All four protocol client modules are aliased so they can be called by name
  without a prefix in each test file: OAuthClient, SAMLServiceProvider,
  SCIMConsumer, WebAuthnAuthenticator.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      use AuthifyWeb.ConnCase, async: true

      alias AuthifyTest.OAuthClient
      alias AuthifyTest.SAMLServiceProvider
      alias AuthifyTest.SCIMConsumer
      alias AuthifyTest.WebAuthnAuthenticator
      import AuthifyWeb.IntegrationCase

      setup :setup_integration
    end
  end

  @doc """
  Sets up the integration test context with an org and admin user.
  """
  def setup_integration(_tags) do
    organization = Authify.AccountsFixtures.organization_fixture()
    admin = Authify.AccountsFixtures.admin_user_fixture(organization)
    %{org: organization, admin: admin}
  end
end
