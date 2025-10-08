defmodule AuthifyWeb.UserDashboardHTML do
  use AuthifyWeb, :html

  embed_templates "user_dashboard_html/*"

  def app_icon(app_type) do
    case app_type do
      :oauth2 -> "🔗"
      :saml -> "🔐"
      _ -> "📱"
    end
  end

  def app_link_url(app, type, organization) do
    case type do
      :oauth2 -> ~p"/#{organization.slug}/user/apps/oauth2/#{app.id}"
      :saml -> ~p"/#{organization.slug}/user/apps/saml/#{app.id}"
    end
  end

  def app_description(app, type) do
    case type do
      :oauth2 ->
        if app.description && String.trim(app.description) != "" do
          app.description
        else
          "OAuth2 Application"
        end

      :saml ->
        if app.metadata && String.trim(app.metadata) != "" do
          # Try to extract description from metadata if available
          "SAML Service Provider"
        else
          "SAML Service Provider"
        end
    end
  end
end
