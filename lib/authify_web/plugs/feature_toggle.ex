defmodule AuthifyWeb.Plugs.FeatureToggle do
  @moduledoc """
  Plug that halts a request when a default-enabled organization feature toggle is
  disabled.

  This generalizes the pattern used for the SCIM inbound toggle: a feature is
  considered enabled unless explicitly set to `false`, and disabled features
  return a 404 so they are not advertised.

  ## Options

    * `:feature` (required) - the organization setting name, e.g. `:allow_saml`
    * `:message` - response body when the feature is disabled

  The plug requires `conn.assigns.current_organization` to be set by the
  `AuthifyWeb.Plugs.OrganizationPlug`, which must run earlier in the pipeline.
  """
  import Plug.Conn

  alias Authify.Configurations

  def init(opts), do: opts

  def call(conn, opts) do
    organization = conn.assigns[:current_organization]
    feature = Keyword.fetch!(opts, :feature)

    if organization && Configurations.feature_enabled?(organization, feature) do
      conn
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(
        :not_found,
        Keyword.get(opts, :message, "Feature is not enabled for this organization")
      )
      |> halt()
    end
  end
end
