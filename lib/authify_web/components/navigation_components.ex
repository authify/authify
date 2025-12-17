defmodule AuthifyWeb.NavigationComponents do
  @moduledoc """
  Reusable navigation components for Authify.
  """
  use Phoenix.Component
  use AuthifyWeb, :verified_routes

  @doc """
  Renders the organization sidebar navigation.

  ## Examples

      <.organization_sidebar user={@user} organization={@organization} current_page="dashboard" />
  """
  attr :user, :map, required: true
  attr :organization, :map, required: true
  attr :current_page, :string, default: ""

  def organization_sidebar(assigns) do
    # Check if user is admin to determine navigation type
    assigns = assign(assigns, :is_admin, admin_user?(assigns.user, assigns.organization))

    ~H"""
    <nav class="col-md-3 col-lg-2 d-md-block bg-body-tertiary sidebar collapse">
      <div class="position-sticky pt-3">
        <div class="px-3 pb-3 mb-3 border-bottom">
          <a href="/" class="d-flex align-items-center text-decoration-none">
            <img
              src={~p"/images/logo-no-text.svg"}
              alt="Authify"
              width="32"
              height="32"
              class="me-2"
            />
            <span class="fs-5 fw-semibold">Authify</span>
          </a>
        </div>
        <div class="px-3 pb-3 border-bottom">
          <h6 class="text-muted">Organization</h6>
          <h5>{@organization.name}</h5>
          <small class="text-muted">{@organization.slug}</small>

          <%= if Authify.Accounts.User.super_admin?(@user) and @organization.slug != "authify-global" do %>
            <div class="mt-2">
              <.form
                for={%{}}
                action={~p"/#{@organization.slug}/switch/global"}
                method="post"
                class="m-0"
              >
                <button
                  type="submit"
                  class="btn btn-warning btn-sm w-100"
                  title="Return to Global Admin view"
                >
                  <i class="bi bi-arrow-left"></i> Return to Global
                </button>
              </.form>
            </div>
          <% end %>
        </div>

        <ul class="nav flex-column mt-3">
          <%= if @is_admin do %>
            <!-- Admin Navigation -->
            <li class="nav-item">
              <a
                class={["nav-link", if(@current_page == "dashboard", do: "active", else: "")]}
                aria-current={if @current_page == "dashboard", do: "page", else: false}
                href={"/#{@organization.slug}/dashboard"}
              >
                <i class="bi bi-house"></i> Dashboard
              </a>
            </li>
          <% else %>
            <!-- Regular User Navigation -->
            <li class="nav-item">
              <a
                class={["nav-link", if(@current_page == "user_dashboard", do: "active", else: "")]}
                aria-current={if @current_page == "user_dashboard", do: "page", else: false}
                href={"/#{@organization.slug}/user/dashboard"}
              >
                <i class="bi bi-grid"></i> My Applications
              </a>
            </li>
          <% end %>

          <%= if @is_admin do %>
            <!-- Admin-only navigation items -->
            <li class="nav-item">
              <a
                class={["nav-link", if(@current_page == "users", do: "active", else: "")]}
                aria-current={if @current_page == "users", do: "page", else: false}
                href={"/#{@organization.slug}/users"}
              >
                <i class="bi bi-people"></i>
                <%= if @organization.slug == "authify-global" do %>
                  Global Admins
                <% else %>
                  Users
                <% end %>
              </a>
            </li>
            <li class="nav-item">
              <a
                class={["nav-link", if(@current_page == "invitations", do: "active", else: "")]}
                aria-current={if @current_page == "invitations", do: "page", else: false}
                href={"/#{@organization.slug}/invitations"}
              >
                <i class="bi bi-envelope-plus"></i> Invitations
              </a>
            </li>
            <li class="nav-item">
              <a
                class={["nav-link", if(@current_page == "audit_logs", do: "active", else: "")]}
                aria-current={if @current_page == "audit_logs", do: "page", else: false}
                href={"/#{@organization.slug}/audit_logs"}
              >
                <i class="bi bi-shield-check"></i> Audit Logs
              </a>
            </li>
          <% end %>

          <%= if @is_admin do %>
            <%= if @organization.slug == "authify-global" do %>
              <!-- Global Admin Only Menu Items -->
              <li class="nav-item">
                <a
                  class={["nav-link", if(@current_page == "organizations", do: "active", else: "")]}
                  aria-current={if @current_page == "organizations", do: "page", else: false}
                  href={"/#{@organization.slug}/organizations"}
                >
                  <i class="bi bi-building"></i> Organizations
                </a>
              </li>
              <li class="nav-item">
                <a
                  class={["nav-link", if(@current_page == "analytics", do: "active", else: "")]}
                  aria-current={if @current_page == "analytics", do: "page", else: false}
                  href={"/#{@organization.slug}/analytics"}
                >
                  <i class="bi bi-graph-up"></i> Analytics
                </a>
              </li>
              <li class="nav-item">
                <a
                  class={["nav-link", if(@current_page == "maintenance", do: "active", else: "")]}
                  aria-current={if @current_page == "maintenance", do: "page", else: false}
                  href={"/#{@organization.slug}/maintenance"}
                >
                  <i class="bi bi-tools"></i> Maintenance
                </a>
              </li>
            <% else %>
              <!-- Regular Organization Admin Menu Items -->
              <li class="nav-item">
                <a
                  class={["nav-link", if(@current_page == "applications", do: "active", else: "")]}
                  aria-current={if @current_page == "applications", do: "page", else: false}
                  href={"/#{@organization.slug}/applications"}
                >
                  <i class="bi bi-app-indicator"></i> Applications
                </a>
              </li>
              <li class="nav-item">
                <a
                  class={["nav-link", if(@current_page == "saml_providers", do: "active", else: "")]}
                  aria-current={if @current_page == "saml_providers", do: "page", else: false}
                  href={"/#{@organization.slug}/saml_providers"}
                >
                  <i class="bi bi-shield-check"></i> SAML Providers
                </a>
              </li>
              <li class="nav-item">
                <a
                  class={["nav-link", if(@current_page == "certificates", do: "active", else: "")]}
                  aria-current={if @current_page == "certificates", do: "page", else: false}
                  href={"/#{@organization.slug}/certificates"}
                >
                  <i class="bi bi-shield-lock"></i> IdP Certificates
                </a>
              </li>
              <li class="nav-item">
                <a
                  class={[
                    "nav-link",
                    if(@current_page == "application_groups", do: "active", else: "")
                  ]}
                  aria-current={if @current_page == "application_groups", do: "page", else: false}
                  href={"/#{@organization.slug}/application_groups"}
                >
                  <i class="bi bi-people-fill"></i> Application Groups
                </a>
              </li>
            <% end %>
            <li class="nav-item">
              <a
                class={[
                  "nav-link",
                  if(@current_page == "organization_settings", do: "active", else: "")
                ]}
                aria-current={if @current_page == "organization_settings", do: "page", else: false}
                href={"/#{@organization.slug}/settings"}
              >
                <i class="bi bi-gear"></i> Settings
              </a>
            </li>
          <% end %>
        </ul>

        <div class="mt-auto pt-3 border-top">
          <div class="px-3 pb-2">
            <small class="text-muted">Signed in as</small>
            <br />
            <strong>{Authify.Accounts.User.full_name(@user)}</strong>
            <br />
            <small class="text-muted">{@user.email}</small>
          </div>
          <ul class="nav flex-column">
            <%= if Authify.Accounts.User.active_member_of?(@user, @organization.id) do %>
              <li class="nav-item">
                <a
                  class={["nav-link", if(@current_page == "profile", do: "active", else: "")]}
                  aria-current={if @current_page == "profile", do: "page", else: false}
                  href={"/#{@organization.slug}/profile"}
                >
                  <i class="bi bi-person-circle"></i> My Profile
                </a>
              </li>
            <% end %>
            <li class="nav-item">
              <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#logoutModal">
                <i class="bi bi-box-arrow-right"></i> Sign Out
              </a>
            </li>
          </ul>
        </div>
      </div>
    </nav>
    """
  end

  @doc """
  Renders the logout modal that's used across multiple pages.
  """
  def logout_modal(assigns) do
    ~H"""
    <div
      class="modal fade"
      id="logoutModal"
      tabindex="-1"
      aria-labelledby="logoutModalLabel"
      aria-hidden="true"
    >
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="logoutModalLabel">Sign Out</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close">
            </button>
          </div>
          <div class="modal-body">
            Are you sure you want to sign out?
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <.form for={%{}} action={~p"/logout"} method="delete">
              <button type="submit" class="btn btn-primary">Sign Out</button>
            </.form>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # Helper to determine if user has admin privileges in the current organization
  defp admin_user?(user, organization) do
    Authify.Accounts.User.admin?(user, organization.id) or
      Authify.Accounts.User.global_admin?(user)
  end
end
