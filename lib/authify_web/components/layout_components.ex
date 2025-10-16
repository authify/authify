defmodule AuthifyWeb.LayoutComponents do
  @moduledoc """
  Reusable layout components for Authify.
  """
  use Phoenix.Component

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
    <div class="bg-body-secondary flex-grow-1 d-flex align-items-center">
      <div class="container">
        <AuthifyWeb.Layouts.flash_group flash={@flash} />
        {render_slot(@inner_block)}
      </div>
    </div>
    """
  end
end
