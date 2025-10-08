defmodule AuthifyWeb.CoreComponents do
  @moduledoc """
  Provides core UI components.

  At first glance, this module may seem daunting, but its goal is to provide
  core building blocks for your application, such as tables, forms, and
  inputs. The components consist mostly of markup and are well-documented
  with doc strings and declarative assigns. You may customize and style
  them in any way you want, based on your application growth and needs.

  The foundation for styling is Bootstrap 5.3, a powerful CSS framework
  that provides responsive design components and utilities. Here are useful references:

    * [Bootstrap Components](https://getbootstrap.com/docs/5.3/components/) - comprehensive
      component library for forms, buttons, cards, navigation, and more.

    * [Bootstrap Utilities](https://getbootstrap.com/docs/5.3/utilities/) - utility classes
      for spacing, typography, colors, flexbox, and responsive design.

    * [Bootstrap Icons](https://icons.getbootstrap.com/) - icon library used throughout
      the application.

    * [Phoenix.Component](https://hexdocs.pm/phoenix_live_view/Phoenix.Component.html) -
      the component system used by Phoenix. Some components, such as `<.link>`
      and `<.form>`, are defined there.

  """
  use Phoenix.Component
  use Gettext, backend: AuthifyWeb.Gettext

  alias Phoenix.LiveView.JS

  @doc """
  Renders flash notices.

  ## Examples

      <.flash kind={:info} flash={@flash} />
      <.flash kind={:info} phx-mounted={show("#flash")}>Welcome Back!</.flash>
  """
  attr :id, :string, doc: "the optional id of flash container"
  attr :flash, :map, default: %{}, doc: "the map of flash messages to display"
  attr :title, :string, default: nil
  attr :kind, :atom, values: [:info, :error], doc: "used for styling and flash lookup"
  attr :rest, :global, doc: "the arbitrary HTML attributes to add to the flash container"

  slot :inner_block, doc: "the optional inner block that renders the flash message"

  def flash(assigns) do
    assigns = assign_new(assigns, :id, fn -> "flash-#{assigns.kind}" end)

    ~H"""
    <div
      :if={msg = render_slot(@inner_block) || Phoenix.Flash.get(@flash, @kind)}
      id={@id}
      role="alert"
      class={[
        "alert alert-dismissible fade show",
        @kind == :info && "alert-success",
        @kind == :error && "alert-danger"
      ]}
      {@rest}
    >
      <i :if={@kind == :info} class="bi bi-check-circle-fill me-2"></i>
      <i :if={@kind == :error} class="bi bi-exclamation-triangle-fill me-2"></i>
      <strong :if={@title}>{@title}</strong>
      {msg}
      <button
        type="button"
        class="btn-close"
        data-bs-dismiss="alert"
        aria-label="Close"
        phx-click={JS.push("lv:clear-flash", value: %{key: @kind}) |> hide("##{@id}")}
      >
      </button>
    </div>
    """
  end

  @doc """
  Renders a button with navigation support.

  ## Examples

      <.button>Send!</.button>
      <.button phx-click="go" variant="primary">Send!</.button>
      <.button navigate={~p"/"}>Home</.button>
  """
  attr :rest, :global, include: ~w(href navigate patch method download name value disabled)
  attr :class, :string
  attr :variant, :string, values: ~w(primary)
  slot :inner_block, required: true

  def button(%{rest: rest} = assigns) do
    variants = %{"primary" => "btn-primary", nil => "btn-primary btn-soft"}

    assigns =
      assign_new(assigns, :class, fn ->
        ["btn", Map.fetch!(variants, assigns[:variant])]
      end)

    if rest[:href] || rest[:navigate] || rest[:patch] do
      ~H"""
      <.link class={@class} {@rest}>
        {render_slot(@inner_block)}
      </.link>
      """
    else
      ~H"""
      <button class={@class} {@rest}>
        {render_slot(@inner_block)}
      </button>
      """
    end
  end

  @doc """
  Renders an input with label and error messages.

  A `Phoenix.HTML.FormField` may be passed as argument,
  which is used to retrieve the input name, id, and values.
  Otherwise all attributes may be passed explicitly.

  ## Types

  This function accepts all HTML input types, considering that:

    * You may also set `type="select"` to render a `<select>` tag

    * `type="checkbox"` is used exclusively to render boolean values

    * For live file uploads, see `Phoenix.Component.live_file_input/1`

  See https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input
  for more information. Unsupported types, such as hidden and radio,
  are best written directly in your templates.

  ## Examples

      <.input field={@form[:email]} type="email" />
      <.input name="my-input" errors={["oh no!"]} />
  """
  attr :id, :any, default: nil
  attr :name, :any
  attr :label, :string, default: nil
  attr :value, :any

  attr :type, :string,
    default: "text",
    values: ~w(checkbox color date datetime-local email file month number password
               search select tel text textarea time url week)

  attr :field, Phoenix.HTML.FormField,
    doc: "a form field struct retrieved from the form, for example: @form[:email]"

  attr :errors, :list, default: []
  attr :checked, :boolean, doc: "the checked flag for checkbox inputs"
  attr :prompt, :string, default: nil, doc: "the prompt for select inputs"
  attr :options, :list, doc: "the options to pass to Phoenix.HTML.Form.options_for_select/2"
  attr :multiple, :boolean, default: false, doc: "the multiple flag for select inputs"
  attr :class, :string, default: nil, doc: "the input class to use over defaults"
  attr :error_class, :string, default: nil, doc: "the input error class to use over defaults"

  attr :rest, :global,
    include: ~w(accept autocomplete capture cols disabled form list max maxlength min minlength
                multiple pattern placeholder readonly required rows size step)

  def input(%{field: %Phoenix.HTML.FormField{} = field} = assigns) do
    errors = if Phoenix.Component.used_input?(field), do: field.errors, else: []

    assigns
    |> assign(field: nil, id: assigns.id || field.id)
    |> assign(:errors, Enum.map(errors, &translate_error(&1)))
    |> assign_new(:name, fn -> if assigns.multiple, do: field.name <> "[]", else: field.name end)
    |> assign_new(:value, fn -> field.value end)
    |> input()
  end

  def input(%{type: "checkbox"} = assigns) do
    assigns =
      assign_new(assigns, :checked, fn ->
        Phoenix.HTML.Form.normalize_value("checkbox", assigns[:value])
      end)

    ~H"""
    <div class="mb-3">
      <div class="form-check">
        <input type="hidden" name={@name} value="false" disabled={@rest[:disabled]} />
        <input
          type="checkbox"
          id={@id}
          name={@name}
          value="true"
          checked={@checked}
          class={@class || "form-check-input"}
          {@rest}
        />
        <label class="form-check-label" for={@id}>
          {@label}
        </label>
      </div>
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  def input(%{type: "select"} = assigns) do
    ~H"""
    <div class="fieldset mb-2">
      <label>
        <span :if={@label} class="label mb-1">{@label}</span>
        <select
          id={@id}
          name={@name}
          class={[@class || "w-full select", @errors != [] && (@error_class || "select-error")]}
          multiple={@multiple}
          {@rest}
        >
          <option :if={@prompt} value="">{@prompt}</option>
          {Phoenix.HTML.Form.options_for_select(@options, @value)}
        </select>
      </label>
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  def input(%{type: "textarea"} = assigns) do
    ~H"""
    <div class="fieldset mb-2">
      <label>
        <span :if={@label} class="label mb-1">{@label}</span>
        <textarea
          id={@id}
          name={@name}
          class={[
            @class || "w-full textarea",
            @errors != [] && (@error_class || "textarea-error")
          ]}
          {@rest}
        >{Phoenix.HTML.Form.normalize_value("textarea", @value)}</textarea>
      </label>
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  # All other inputs text, datetime-local, url, password, etc. are handled here...
  def input(assigns) do
    ~H"""
    <div class="fieldset mb-2">
      <label>
        <span :if={@label} class="form-label mb-1">{@label}</span>
        <input
          type={@type}
          name={@name}
          id={@id}
          value={Phoenix.HTML.Form.normalize_value(@type, @value)}
          class={[
            @class || "form-control w-100",
            @errors != [] && (@error_class || "is-invalid")
          ]}
          {@rest}
        />
      </label>
      <.error :for={msg <- @errors}>{msg}</.error>
    </div>
    """
  end

  # Helper used by inputs to generate form errors
  defp error(assigns) do
    ~H"""
    <p class="mt-1 d-flex align-items-center text-danger small">
      <i class="bi bi-exclamation-circle me-2"></i>
      {render_slot(@inner_block)}
    </p>
    """
  end

  @doc """
  Renders a header with title.
  """
  slot :inner_block, required: true
  slot :subtitle
  slot :actions

  def header(assigns) do
    ~H"""
    <header class={[@actions != [] && "d-flex align-items-center justify-content-between", "pb-4"]}>
      <div>
        <h1 class="fs-4 fw-semibold lh-base">
          {render_slot(@inner_block)}
        </h1>
        <p :if={@subtitle != []} class="small text-muted">
          {render_slot(@subtitle)}
        </p>
      </div>
      <div class="flex-shrink-0">{render_slot(@actions)}</div>
    </header>
    """
  end

  @doc """
  Renders a table with generic styling.

  ## Examples

      <.table id="users" rows={@users}>
        <:col :let={user} label="id">{user.id}</:col>
        <:col :let={user} label="username">{user.username}</:col>
      </.table>
  """
  attr :id, :string, required: true
  attr :rows, :list, required: true
  attr :row_id, :any, default: nil, doc: "the function for generating the row id"
  attr :row_click, :any, default: nil, doc: "the function for handling phx-click on each row"

  attr :row_item, :any,
    default: &Function.identity/1,
    doc: "the function for mapping each row before calling the :col and :action slots"

  slot :col, required: true do
    attr :label, :string
  end

  slot :action, doc: "the slot for showing user actions in the last table column"

  def table(assigns) do
    assigns =
      with %{rows: %Phoenix.LiveView.LiveStream{}} <- assigns do
        assign(assigns, row_id: assigns.row_id || fn {id, _item} -> id end)
      end

    ~H"""
    <table class="table table-zebra">
      <thead>
        <tr>
          <th :for={col <- @col}>{col[:label]}</th>
          <th :if={@action != []}>
            <span class="sr-only">{gettext("Actions")}</span>
          </th>
        </tr>
      </thead>
      <tbody id={@id} phx-update={is_struct(@rows, Phoenix.LiveView.LiveStream) && "stream"}>
        <tr :for={row <- @rows} id={@row_id && @row_id.(row)}>
          <td
            :for={col <- @col}
            phx-click={@row_click && @row_click.(row)}
            class={@row_click && "cursor-pointer"}
          >
            {render_slot(col, @row_item.(row))}
          </td>
          <td :if={@action != []} class="text-nowrap fw-semibold">
            <div class="d-flex gap-2">
              <%= for action <- @action do %>
                {render_slot(action, @row_item.(row))}
              <% end %>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    """
  end

  @doc """
  Renders a data list.

  ## Examples

      <.list>
        <:item title="Title">{@post.title}</:item>
        <:item title="Views">{@post.views}</:item>
      </.list>
  """
  slot :item, required: true do
    attr :title, :string, required: true
  end

  def list(assigns) do
    ~H"""
    <ul class="list">
      <li :for={item <- @item} class="list-row">
        <div class="list-col-grow">
          <div class="font-bold">{item.title}</div>
          <div>{render_slot(item)}</div>
        </div>
      </li>
    </ul>
    """
  end

  @doc """
  Renders a Bootstrap select dropdown with proper styling.

  ## Examples

      <.bootstrap_select field={f[:usage]} label="Usage" options={[{"Option 1", "value1"}]} />
      <.bootstrap_select field={f[:status]} label="Status" options={status_options()} required />
  """
  attr :field, Phoenix.HTML.FormField,
    doc: "a form field struct retrieved from the form, for example: @form[:email]"

  attr :label, :string, default: nil, doc: "the label for the select field"
  attr :options, :list, required: true, doc: "list of {label, value} tuples for select options"
  attr :required, :boolean, default: false, doc: "whether the field is required"
  attr :class, :string, default: nil, doc: "additional CSS classes for the select element"
  attr :help_text, :string, default: nil, doc: "help text to display below the select"
  attr :rest, :global

  def bootstrap_select(%{field: %Phoenix.HTML.FormField{} = field} = assigns) do
    errors = if Phoenix.Component.used_input?(field), do: field.errors, else: []

    assigns =
      assigns
      |> assign(field: nil)
      |> assign(:id, Map.get(assigns, :id, field.id))
      |> assign(:errors, Enum.map(errors, &translate_error(&1)))
      |> assign_new(:name, fn -> field.name end)
      |> assign_new(:value, fn -> field.value end)

    ~H"""
    <div class="mb-3">
      <label :if={@label} for={@id} class="form-label">
        {@label}
        <span :if={@required} class="text-danger">*</span>
      </label>
      <select
        id={@id}
        name={@name}
        class={[
          "form-select",
          @errors != [] && "is-invalid",
          @class
        ]}
        required={@required}
        {@rest}
      >
        <%= for {label, value} <- @options do %>
          <option
            value={value}
            selected={Phoenix.HTML.Form.normalize_value("select", @value) == value}
          >
            {label}
          </option>
        <% end %>
      </select>
      <div :if={@help_text} class="form-text">{@help_text}</div>
      <%= if @errors != [] do %>
        <div class="invalid-feedback d-block">
          {Enum.join(@errors, ", ")}
        </div>
      <% end %>
    </div>
    """
  end

  @doc """
  Renders a [Heroicon](https://heroicons.com).

  Heroicons come in three styles – outline, solid, and mini.
  By default, the outline style is used, but solid and mini may
  be applied by using the `-solid` and `-mini` suffix.

  You can customize the size and colors of the icons by setting
  width, height, and background color classes.

  Icons are extracted from the `deps/heroicons` directory and bundled within
  your compiled app.css by the plugin in `assets/vendor/heroicons.js`.

  ## Examples

      <.icon name="hero-x-mark" />
      <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
  """
  attr :name, :string, required: true
  attr :class, :string, default: "size-4"

  def icon(%{name: "hero-" <> _} = assigns) do
    ~H"""
    <span class={[@name, @class]} />
    """
  end

  ## JS Commands

  def show(js \\ %JS{}, selector) do
    JS.show(js,
      to: selector,
      time: 300,
      transition:
        {"transition-all ease-out duration-300",
         "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95",
         "opacity-100 translate-y-0 sm:scale-100"}
    )
  end

  def hide(js \\ %JS{}, selector) do
    JS.hide(js,
      to: selector,
      time: 200,
      transition:
        {"transition-all ease-in duration-200", "opacity-100 translate-y-0 sm:scale-100",
         "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"}
    )
  end

  @doc """
  Translates an error message using gettext.
  """
  def translate_error({msg, opts}) do
    # When using gettext, we typically pass the strings we want
    # to translate as a static argument:
    #
    #     # Translate the number of files with plural rules
    #     dngettext("errors", "1 file", "%{count} files", count)
    #
    # However the error messages in our forms and APIs are generated
    # dynamically, so we need to translate them by calling Gettext
    # with our gettext backend as first argument. Translations are
    # available in the errors.po file (as we use the "errors" domain).
    if count = opts[:count] do
      Gettext.dngettext(AuthifyWeb.Gettext, "errors", msg, msg, count, opts)
    else
      Gettext.dgettext(AuthifyWeb.Gettext, "errors", msg, opts)
    end
  end

  @doc """
  Translates the errors for a field from a keyword list of errors.
  """
  def translate_errors(errors, field) when is_list(errors) do
    for {^field, {msg, opts}} <- errors, do: translate_error({msg, opts})
  end

  @doc """
  Renders a filter and sort toolbar for index views.

  ## Examples

      <.filter_sort_toolbar
        base_path="/myorg/users"
        current_sort="email"
        current_order="asc"
        current_search=""
        sort_options={[
          {"Name", "first_name"},
          {"Email", "email"},
          {"Role", "role"},
          {"Joined", "inserted_at"}
        ]}
      >
        <:filter label="Role">
          <select name="role" class="form-select form-select-sm">
            <option value="">All Roles</option>
            <option value="admin">Admin</option>
            <option value="user">User</option>
          </select>
        </:filter>
        <:filter label="Status">
          <select name="status" class="form-select form-select-sm">
            <option value="">Active Only</option>
            <option value="all">All Users</option>
            <option value="false">Inactive Only</option>
          </select>
        </:filter>
      </.filter_sort_toolbar>
  """
  attr :base_path, :string, required: true, doc: "Base path for the form action"
  attr :current_sort, :string, default: "email", doc: "Current sort field"
  attr :current_order, :string, default: "asc", doc: "Current sort order"
  attr :current_search, :string, default: nil, doc: "Current search term"

  attr :sort_options, :list,
    required: true,
    doc: "List of {label, value} tuples for sort field options"

  slot :filter, doc: "Filter controls" do
    attr :label, :string, doc: "Label for the filter"
  end

  def filter_sort_toolbar(assigns) do
    ~H"""
    <div class="card mb-3">
      <div class="card-body">
        <form method="get" action={@base_path} class="row g-3" id="filter-form">
          <!-- Preserve current sort parameters -->
          <input type="hidden" name="sort" value={@current_sort} />
          <input type="hidden" name="order" value={@current_order} />
          
    <!-- Search -->
          <div class="col-md-6">
            <label class="form-label small text-muted">Search</label>
            <input
              type="text"
              name="search"
              value={@current_search}
              placeholder="Search..."
              class="form-control form-control-sm"
              onkeypress="if(event.key === 'Enter') { this.form.submit(); }"
            />
          </div>
          
    <!-- Additional Filters -->
          <div :for={filter <- @filter} class="col-md-auto">
            <label class="form-label small text-muted">{filter.label}</label>
            {render_slot(filter)}
          </div>
          
    <!-- Actions -->
          <div class="col-md-auto d-flex align-items-end">
            <div class="btn-group">
              <button type="submit" class="btn btn-sm btn-primary">
                <i class="bi bi-funnel"></i> Apply
              </button>
              <a href={@base_path} class="btn btn-sm btn-outline-secondary">
                <i class="bi bi-x-circle"></i> Clear
              </a>
            </div>
          </div>
        </form>

        <script>
          // Auto-submit form when any select changes
          document.getElementById('filter-form').querySelectorAll('select').forEach(function(select) {
            select.addEventListener('change', function() {
              this.form.submit();
            });
          });
        </script>
      </div>
    </div>
    """
  end

  @doc """
  Renders a sortable table header that updates the URL with sort parameters.

  ## Examples

      <.sortable_header
        field="email"
        label="Email"
        current_sort="email"
        current_order="asc"
        base_path="/myorg/users"
        params={%{"search" => "test", "role" => "admin"}}
      />
  """
  attr :field, :string, required: true, doc: "The field name to sort by"
  attr :label, :string, required: true, doc: "The display label for the header"
  attr :current_sort, :string, required: true, doc: "Current sort field"
  attr :current_order, :string, required: true, doc: "Current sort order"
  attr :base_path, :string, required: true, doc: "Base path for the link"
  attr :params, :map, default: %{}, doc: "Additional query parameters to preserve"

  def sortable_header(assigns) do
    # Determine next order: if clicking current sort field, toggle; otherwise start with asc
    {next_order, icon} =
      if assigns.field == assigns.current_sort do
        case assigns.current_order do
          "asc" -> {"desc", "bi-arrow-up"}
          "desc" -> {"", "bi-arrow-down"}
          _ -> {"asc", ""}
        end
      else
        {"asc", ""}
      end

    # Build query parameters
    query_params =
      if next_order == "" do
        # Remove sorting when clicking third time
        Map.drop(assigns.params, ["sort", "order"])
      else
        Map.merge(assigns.params, %{"sort" => assigns.field, "order" => next_order})
      end

    # Remove nil and empty values
    query_params =
      Enum.reject(query_params, fn {_k, v} -> is_nil(v) || v == "" end)
      |> Map.new()

    assigns =
      assign(assigns,
        next_order: next_order,
        icon: icon,
        query_params: query_params
      )

    ~H"""
    <th class="user-select-none">
      <a
        href={@base_path <> "?" <> URI.encode_query(@query_params)}
        class="text-decoration-none text-body d-flex align-items-center"
        style="cursor: pointer;"
      >
        {@label}
        <%= if @field == @current_sort do %>
          <i class={"bi #{@icon} ms-1"}></i>
        <% end %>
      </a>
    </th>
    """
  end
end
