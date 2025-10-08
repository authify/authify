defmodule AuthifyWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use AuthifyWeb, :html

  # Embed all files in layouts/* within this module.
  # The default root.html.heex file contains the HTML
  # skeleton of your application, namely HTML headers
  # and other static content.
  embed_templates "layouts/*"

  @doc """
  Renders your app layout.

  This function is typically invoked from every template,
  and it often contains your application menu, sidebar,
  or similar.

  ## Examples

      <Layouts.app flash={@flash}>
        <h1>Content</h1>
      </Layouts.app>

  """
  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current [scope](https://hexdocs.pm/phoenix/scopes.html)"

  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <header class="navbar navbar-expand-lg bg-body-tertiary px-4">
      <div class="container-fluid">
        <a href="/" class="navbar-brand d-flex align-items-center">
          <img src={~p"/images/logo.svg"} width="36" class="me-2" />
          <span class="fs-6 fw-semibold">v{Application.spec(:phoenix, :vsn)}</span>
        </a>
        <div class="navbar-nav ms-auto">
          <ul class="navbar-nav d-flex flex-row align-items-center">
            <li class="nav-item me-3">
              <a href="https://phoenixframework.org/" class="btn btn-outline-secondary btn-sm">
                Website
              </a>
            </li>
            <li class="nav-item me-3">
              <a
                href="https://github.com/phoenixframework/phoenix"
                class="btn btn-outline-secondary btn-sm"
              >
                GitHub
              </a>
            </li>
            <li class="nav-item">
              <a href="https://hexdocs.pm/phoenix/overview.html" class="btn btn-primary btn-sm">
                Get Started <span aria-hidden="true">&rarr;</span>
              </a>
            </li>
          </ul>
        </div>
      </div>
    </header>

    <main class="container my-5">
      <div class="row justify-content-center">
        <div class="col-lg-8">
          {render_slot(@inner_block)}
        </div>
      </div>
    </main>

    <.flash_group flash={@flash} />
    """
  end

  @doc """
  Gets the user's theme preference from the connection.
  Returns "auto", "light", or "dark".
  """
  def get_user_theme_preference(conn) do
    case conn.assigns[:current_user] do
      nil -> "auto"
      user -> user.theme_preference || "auto"
    end
  end

  @doc """
  Gets the effective theme to apply based on user preference.
  For server-side rendering, "auto" defaults to "light".
  The JavaScript will handle the actual auto-detection.
  """
  def get_theme(conn) do
    preference = get_user_theme_preference(conn)

    case preference do
      "auto" -> "light"
      "light" -> "light"
      "dark" -> "dark"
      _ -> "light"
    end
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title={gettext("We can't find the internet")}
        phx-disconnected={show(".phx-client-error #client-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={gettext("Something went wrong!")}
        phx-disconnected={show(".phx-server-error #server-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end
end
