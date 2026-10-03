defmodule AuthifyWeb.Components.FeatureComponents do
  @moduledoc """
  Shared components for rendering organization feature-toggle state.
  """
  use Phoenix.Component

  @doc """
  Renders a warning banner when an organization feature is disabled.

  The banner is intended to sit at the top of a section whose configuration
  remains available so admins can stage settings ahead of enabling the feature.
  It renders nothing when the feature is enabled.

  ## Attributes

    * `:enabled` - whether the feature is currently enabled
    * `:feature_label` - human-readable feature name, e.g. `"SAML"`
    * `:organization` - the current organization (for the settings link)
    * `:message` - explains what will not work while the feature is disabled
  """
  attr :enabled, :boolean, required: true
  attr :feature_label, :string, required: true
  attr :organization, :map, required: true
  attr :message, :string, required: true

  def feature_disabled_banner(assigns) do
    ~H"""
    <div :if={!@enabled} class="alert alert-warning" role="alert">
      <i class="bi bi-exclamation-triangle"></i>
      <strong>{@feature_label} is disabled</strong>
      <p class="mb-0">
        {@message} It can be configured now, but will not take effect until it is enabled in <a
          href={"/#{@organization.slug}/settings/configuration"}
          class="alert-link"
        >
          organization settings
        </a>.
      </p>
    </div>
    """
  end
end
