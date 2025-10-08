defmodule AuthifyWeb.LayoutComponents do
  @moduledoc """
  Reusable layout components for Authify.
  """
  use Phoenix.Component
  import Plug.CSRFProtection, only: [get_csrf_token: 0]

  @doc """
  Renders a two-column layout with sidebar and main content.

  ## Examples

      <.two_column_layout>
        <:sidebar>
          <.organization_sidebar user={@user} organization={@organization} current_page="dashboard" />
        </:sidebar>

        <:main>
          <h1>Main content goes here</h1>
        </:main>
      </.two_column_layout>
  """
  slot :sidebar, required: true
  slot :main, required: true
  attr :flash, :map, default: %{}

  def two_column_layout(assigns) do
    ~H"""
    <div class="container-fluid">
      <div class="row">
        {render_slot(@sidebar)}
        
    <!-- Main content -->
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
          <AuthifyWeb.Layouts.flash_group flash={@flash} />
          {render_slot(@main)}
        </main>
      </div>
    </div>
    """
  end

  @doc """
  Renders a simple authentication layout for login, signup, and setup pages.
  Provides a clean, centered layout without navigation.

  ## Examples

      <.auth_layout>
        <h1>Welcome to Authify</h1>
        <p>Please sign in to continue</p>
      </.auth_layout>
  """
  slot :inner_block, required: true
  attr :flash, :map, default: %{}

  def auth_layout(assigns) do
    ~H"""
    <!DOCTYPE html>
    <html lang="en" class="h-100">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="csrf-token" content={get_csrf_token()} />
        <title data-default="Authify" data-suffix=" · Authify">Authify</title>
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="alternate icon" href="/favicon.ico" />
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
          rel="stylesheet"
          integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN"
          crossorigin="anonymous"
        />
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css"
        />
        <link phx-track-static rel="stylesheet" href="/assets/css/app.css" />
        <script defer phx-track-static type="text/javascript" src="/assets/js/app.js">
        </script>
        <script
          src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"
          integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL"
          crossorigin="anonymous"
        >
        </script>
      </head>
      <body class="bg-body-secondary d-flex align-items-center min-vh-100">
        <div class="container">
          <AuthifyWeb.Layouts.flash_group flash={@flash} />
          {render_slot(@inner_block)}
        </div>
      </body>
    </html>
    """
  end
end
