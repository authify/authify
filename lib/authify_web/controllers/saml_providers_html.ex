defmodule AuthifyWeb.SAMLProvidersHTML do
  use AuthifyWeb, :html

  embed_templates "saml_providers_html/*"

  @doc """
  Renders a service provider form.
  """
  attr :changeset, Ecto.Changeset, required: true
  attr :action, :string, required: true

  def service_provider_form(assigns) do
    ~H"""
    <.form for={@changeset} action={@action} id="service-provider-form">
      <%= if @changeset.action do %>
        <div class="alert alert-danger">
          <p>Oops, something went wrong! Please check the errors below.</p>
        </div>
      <% end %>

      <div class="mb-3">
        <label for="service_provider_name" class="form-label">Service Provider Name</label>
        <input
          type="text"
          name="service_provider[name]"
          id="service_provider_name"
          class="form-control"
          placeholder="My SAML App"
          value={
            Map.get(@changeset.changes, :name) ||
              Map.get(@changeset.data, :name) || ""
          }
          required
        />
        <div class="form-text">A friendly name for your SAML service provider</div>
        <%= for {msg, _} <- (Keyword.get_values(@changeset.errors, :name) || []) do %>
          <div class="invalid-feedback d-block">{msg}</div>
        <% end %>
      </div>

      <div class="mb-3">
        <label for="service_provider_entity_id" class="form-label">
          Entity ID
          <button
            type="button"
            class="btn btn-link btn-sm p-0 ms-1"
            data-bs-toggle="modal"
            data-bs-target="#samlHelpModal"
          >
            <i class="bi bi-question-circle"></i>
          </button>
        </label>
        <input
          type="url"
          name="service_provider[entity_id]"
          id="service_provider_entity_id"
          class="form-control"
          placeholder="https://sp.example.com/metadata"
          value={
            Map.get(@changeset.changes, :entity_id) ||
              Map.get(@changeset.data, :entity_id) || ""
          }
          required
        />
        <div class="form-text">
          Unique identifier for the service provider (usually a URL from the SP's metadata).
          <a href="#" data-bs-toggle="modal" data-bs-target="#samlHelpModal">Need help?</a>
        </div>
        <%= for {msg, _} <- (Keyword.get_values(@changeset.errors, :entity_id) || []) do %>
          <div class="invalid-feedback d-block">{msg}</div>
        <% end %>
      </div>

      <div class="mb-3">
        <label for="service_provider_acs_url" class="form-label">
          Assertion Consumer Service URL (ACS)
        </label>
        <input
          type="url"
          name="service_provider[acs_url]"
          id="service_provider_acs_url"
          class="form-control"
          placeholder="https://sp.example.com/saml/acs"
          value={
            Map.get(@changeset.changes, :acs_url) ||
              Map.get(@changeset.data, :acs_url) || ""
          }
          required
        />
        <div class="form-text">
          The endpoint where Authify will POST SAML responses after successful authentication.
          This URL is provided by your service provider's SAML configuration.
        </div>
        <%= for {msg, _} <- (Keyword.get_values(@changeset.errors, :acs_url) || []) do %>
          <div class="invalid-feedback d-block">{msg}</div>
        <% end %>
      </div>

      <div class="mb-3">
        <label for="service_provider_sls_url" class="form-label">
          Single Logout Service URL (SLS)
        </label>
        <input
          type="url"
          name="service_provider[sls_url]"
          id="service_provider_sls_url"
          class="form-control"
          placeholder="https://sp.example.com/saml/sls"
          value={
            Map.get(@changeset.changes, :sls_url) ||
              Map.get(@changeset.data, :sls_url) || ""
          }
        />
        <div class="form-text">
          <em>Optional.</em>
          The endpoint for handling single logout requests. If provided, users logging out will also be logged out from this service.
        </div>
        <%= for {msg, _} <- (Keyword.get_values(@changeset.errors, :sls_url) || []) do %>
          <div class="invalid-feedback d-block">{msg}</div>
        <% end %>
      </div>

      <div class="mb-3">
        <label for="service_provider_certificate" class="form-label">
          SP Certificate (X.509)
        </label>
        <textarea
          name="service_provider[certificate]"
          id="service_provider_certificate"
          class="form-control font-monospace"
          rows="8"
          placeholder="-----BEGIN CERTIFICATE-----
    ...certificate content...
    -----END CERTIFICATE-----"
        ><%= Map.get(@changeset.changes, :certificate) || Map.get(@changeset.data, :certificate) || "" %></textarea>
        <div class="form-text">
          <em>Optional.</em>
          Service provider's public certificate in PEM format. Required only if you enable "Require Signed Requests" below.
        </div>
        <%= for {msg, _} <- (Keyword.get_values(@changeset.errors, :certificate) || []) do %>
          <div class="invalid-feedback d-block">{msg}</div>
        <% end %>
      </div>

      <div class="mb-3">
        <label for="service_provider_attribute_mapping" class="form-label">
          Attribute Mapping (JSON)
        </label>
        <textarea
          name="service_provider[attribute_mapping]"
          id="service_provider_attribute_mapping"
          class="form-control font-monospace"
          rows="6"
          placeholder='{"email": "email", "first_name": "first_name", "last_name": "last_name", "name": "{{first_name}} {{last_name}}"}'
        ><%= Map.get(@changeset.changes, :attribute_mapping) || Map.get(@changeset.data, :attribute_mapping) || Authify.SAML.ServiceProvider.default_attribute_mapping() %></textarea>
        <div class="form-text">
          Maps user fields to SAML assertion attributes. Use <code>{"{{ }}"}</code>
          syntax for templates (e.g., <code>{"{{first_name}} {{last_name}}"}</code>). Default mapping is usually sufficient.
        </div>
        <%= for {msg, _} <- (Keyword.get_values(@changeset.errors, :attribute_mapping) || []) do %>
          <div class="invalid-feedback d-block">{msg}</div>
        <% end %>
      </div>

      <div class="row mb-3">
        <div class="col-md-4">
          <div class="form-check form-switch">
            <input
              type="checkbox"
              name="service_provider[sign_assertions]"
              id="service_provider_sign_assertions"
              class="form-check-input"
              value="true"
              checked={
                Map.get(@changeset.changes, :sign_assertions) ||
                  Map.get(@changeset.data, :sign_assertions) || true
              }
            />
            <label class="form-check-label" for="service_provider_sign_assertions">
              Sign Assertions
            </label>
          </div>
          <div class="form-text small">Digitally sign SAML assertions (recommended)</div>
        </div>
        <div class="col-md-4">
          <div class="form-check form-switch">
            <input
              type="checkbox"
              name="service_provider[sign_requests]"
              id="service_provider_sign_requests"
              class="form-check-input"
              value="true"
              checked={
                Map.get(@changeset.changes, :sign_requests) ||
                  Map.get(@changeset.data, :sign_requests) || false
              }
            />
            <label class="form-check-label" for="service_provider_sign_requests">
              Require Signed Requests
            </label>
          </div>
          <div class="form-text small">SP must sign authentication requests</div>
        </div>
        <div class="col-md-4">
          <div class="form-check form-switch">
            <input
              type="checkbox"
              name="service_provider[is_active]"
              id="service_provider_is_active"
              class="form-check-input"
              value="true"
              checked={
                Map.get(@changeset.changes, :is_active) ||
                  Map.get(@changeset.data, :is_active) || false
              }
            />
            <label class="form-check-label" for="service_provider_is_active">
              Active
            </label>
          </div>
          <div class="form-text small">Enable SSO for this provider</div>
        </div>
      </div>

      <div class="d-grid gap-2 mt-4">
        <button type="submit" class="btn btn-primary">
          <i class="bi bi-plus-circle"></i> Save SAML Provider
        </button>
      </div>
    </.form>

    <!-- SAML Configuration Help Modal -->
    <div
      class="modal fade"
      id="samlHelpModal"
      tabindex="-1"
      aria-labelledby="samlHelpModalLabel"
      aria-hidden="true"
    >
      <div class="modal-dialog modal-xl">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="samlHelpModalLabel">
              <i class="bi bi-shield-lock"></i> SAML Service Provider Configuration Guide
            </h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close">
            </button>
          </div>
          <div class="modal-body">
            <div class="alert alert-info">
              <i class="bi bi-info-circle"></i>
              <strong>Before you begin:</strong>
              Configure Authify as the Identity Provider (IdP) in your service provider's SAML settings.
              Your service provider will provide the values you need to enter below.
            </div>

            <h6 class="mt-4">
              <i class="bi bi-1-circle-fill text-primary"></i> Required Information
            </h6>
            <table class="table table-sm">
              <thead>
                <tr>
                  <th style="width: 25%;">Field</th>
                  <th>Description</th>
                  <th style="width: 35%;">Where to Find It</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Entity ID</strong></td>
                  <td>Unique identifier for the service provider (usually a URI)</td>
                  <td>
                    SP's SAML metadata XML under <code>&lt;EntityDescriptor entityID="..."&gt;</code>
                  </td>
                </tr>
                <tr>
                  <td><strong>ACS URL</strong></td>
                  <td>Endpoint where SAML responses are sent after authentication</td>
                  <td>
                    SP's SAML metadata or settings page. Look for "Assertion Consumer Service URL" or "Reply URL"
                  </td>
                </tr>
              </tbody>
            </table>

            <h6 class="mt-4">
              <i class="bi bi-2-circle-fill text-primary"></i>
              IdP Information to Provide to Your Service Provider
            </h6>
            <div class="card border">
              <div class="card-body bg-body-secondary">
                <p class="mb-2">
                  <strong>IdP Metadata URL:</strong>
                  <code>https://your-authify-domain/saml/metadata</code>
                </p>
                <p class="mb-2">
                  <strong>IdP SSO URL:</strong>
                  <code>https://your-authify-domain/saml/sso</code>
                </p>
                <p class="mb-0">
                  <strong>IdP Entity ID:</strong>
                  <code>https://your-authify-domain/saml/metadata</code>
                </p>
              </div>
            </div>

            <h6 class="mt-4">
              <i class="bi bi-3-circle-fill text-primary"></i> Common Service Provider Examples
            </h6>

            <div class="accordion" id="examplesAccordion">
              <div class="accordion-item">
                <h2 class="accordion-header">
                  <button
                    class="accordion-button collapsed"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#awsExample"
                  >
                    <i class="bi bi-amazon"></i>
                    <span class="ms-2">AWS (Amazon Web Services)</span>
                  </button>
                </h2>
                <div
                  id="awsExample"
                  class="accordion-collapse collapse"
                  data-bs-parent="#examplesAccordion"
                >
                  <div class="accordion-body">
                    <p>
                      <strong>Entity ID:</strong>
                      <code>urn:amazon:webservices</code>
                    </p>
                    <p>
                      <strong>ACS URL:</strong>
                      <code>https://signin.aws.amazon.com/saml</code>
                    </p>
                    <p class="mb-0">
                      <strong>Attribute Mapping:</strong>
                      Include <code>https://aws.amazon.com/SAML/Attributes/Role</code>
                      for role assumption
                    </p>
                  </div>
                </div>
              </div>

              <div class="accordion-item">
                <h2 class="accordion-header">
                  <button
                    class="accordion-button collapsed"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#salesforceExample"
                  >
                    <i class="bi bi-cloud"></i>
                    <span class="ms-2">Salesforce</span>
                  </button>
                </h2>
                <div
                  id="salesforceExample"
                  class="accordion-collapse collapse"
                  data-bs-parent="#examplesAccordion"
                >
                  <div class="accordion-body">
                    <p>
                      <strong>Entity ID:</strong>
                      <code>https://your-domain.my.salesforce.com</code>
                    </p>
                    <p>
                      <strong>ACS URL:</strong>
                      <code>https://your-domain.my.salesforce.com</code>
                    </p>
                    <p class="mb-0">
                      Download metadata from Salesforce Setup → Single Sign-On Settings
                    </p>
                  </div>
                </div>
              </div>

              <div class="accordion-item">
                <h2 class="accordion-header">
                  <button
                    class="accordion-button collapsed"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#slackExample"
                  >
                    <i class="bi bi-slack"></i>
                    <span class="ms-2">Slack</span>
                  </button>
                </h2>
                <div
                  id="slackExample"
                  class="accordion-collapse collapse"
                  data-bs-parent="#examplesAccordion"
                >
                  <div class="accordion-body">
                    <p>
                      <strong>Entity ID:</strong>
                      <code>https://slack.com</code>
                    </p>
                    <p>
                      <strong>ACS URL:</strong>
                      <code>https://your-workspace.slack.com/sso/saml</code>
                    </p>
                    <p class="mb-0">
                      Configure in Slack Admin → Settings & Permissions → Authentication
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div class="alert alert-warning mt-4">
              <i class="bi bi-exclamation-triangle"></i>
              <strong>Security Note:</strong>
              Always enable "Sign Assertions" for production environments. Only enable "Require Signed Requests" if your SP supports request signing.
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
