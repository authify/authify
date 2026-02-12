This is a web application written using the Phoenix web framework.

## Project Information

- **GitHub Repository**: `authify/authify` (https://github.com/authify/authify)
- **Project Name**: Authify - Multi-tenant Identity Provider
- **Tech Stack**: Elixir, Phoenix 1.8.1, MySQL

## Project guidelines

- Use `mix precommit` alias when you are done with all changes and fix any pending issues
- Use the already included and available `:req` (`Req`) library for HTTP requests, **avoid** `:httpoison`, `:tesla`, and `:httpc`. Req is included by default and is the preferred HTTP client for Phoenix apps

### Phoenix v1.8 guidelines

- **Always** begin your LiveView templates with `<Layouts.app flash={@flash} ...>` which wraps all inner content
- The `MyAppWeb.Layouts` module is aliased in the `my_app_web.ex` file, so you can use it without needing to alias it again
- Anytime you run into errors with no `current_scope` assign:
  - You failed to follow the Authenticated Routes guidelines, or you failed to pass `current_scope` to `<Layouts.app>`
  - **Always** fix the `current_scope` error by moving your routes to the proper `live_session` and ensure you pass `current_scope` as needed
- Phoenix v1.8 moved the `<.flash_group>` component to the `Layouts` module. You are **forbidden** from calling `<.flash_group>` outside of the `layouts.ex` module
- Out of the box, `core_components.ex` imports an `<.icon name="hero-x-mark" class="w-5 h-5"/>` component for for hero icons. **Always** use the `<.icon>` component for icons, **never** use `Heroicons` modules or similar
- **Always** use the imported `<.input>` component for form inputs from `core_components.ex` when available. `<.input>` is imported and using it will will save steps and prevent errors
- If you override the default input classes (`<.input class="myclass px-2 py-1 rounded-lg">)`) class with your own values, no default classes are inherited, so your
custom classes must fully style the input


<!-- usage-rules-start -->

<!-- phoenix:elixir-start -->
## Elixir guidelines

- Elixir lists **do not support index based access via the access syntax**

  **Never do this (invalid)**:

      i = 0
      mylist = ["blue", "green"]
      mylist[i]

  Instead, **always** use `Enum.at`, pattern matching, or `List` for index based list access, ie:

      i = 0
      mylist = ["blue", "green"]
      Enum.at(mylist, i)

- Elixir variables are immutable, but can be rebound, so for block expressions like `if`, `case`, `cond`, etc
  you *must* bind the result of the expression to a variable if you want to use it and you CANNOT rebind the result inside the expression, ie:

      # INVALID: we are rebinding inside the `if` and the result never gets assigned
      if connected?(socket) do
        socket = assign(socket, :val, val)
      end

      # VALID: we rebind the result of the `if` to a new variable
      socket =
        if connected?(socket) do
          assign(socket, :val, val)
        end

- **Never** nest multiple modules in the same file as it can cause cyclic dependencies and compilation errors
- **Never** use map access syntax (`changeset[:field]`) on structs as they do not implement the Access behaviour by default. For regular structs, you **must** access the fields directly, such as `my_struct.field` or use higher level APIs that are available on the struct if they exist, `Ecto.Changeset.get_field/2` for changesets
- Elixir's standard library has everything necessary for date and time manipulation. Familiarize yourself with the common `Time`, `Date`, `DateTime`, and `Calendar` interfaces by accessing their documentation as necessary. **Never** install additional dependencies unless asked or for date/time parsing (which you can use the `date_time_parser` package)
- Don't use `String.to_atom/1` on user input (memory leak risk)
- Predicate function names should not start with `is_` and should end in a question mark. Names like `is_thing` should be reserved for guards
- Elixir's builtin OTP primitives like `DynamicSupervisor` and `Registry`, require names in the child spec, such as `{DynamicSupervisor, name: MyApp.MyDynamicSup}`, then you can use `DynamicSupervisor.start_child(MyApp.MyDynamicSup, child_spec)`
- Use `Task.async_stream(collection, callback, options)` for concurrent enumeration with back-pressure. The majority of times you will want to pass `timeout: :infinity` as option

## Mix guidelines

- Read the docs and options before using tasks (by using `mix help task_name`)
- To debug test failures, run tests in a specific file with `mix test test/my_test.exs` or run all previously failed tests with `mix test --failed`
- `mix deps.clean --all` is **almost never needed**. **Avoid** using it unless you have good reason
<!-- phoenix:elixir-end -->

<!-- phoenix:phoenix-start -->
## Phoenix guidelines

- Remember Phoenix router `scope` blocks include an optional alias which is prefixed for all routes within the scope. **Always** be mindful of this when creating routes within a scope to avoid duplicate module prefixes.

- You **never** need to create your own `alias` for route definitions! The `scope` provides the alias, ie:

      scope "/admin", AppWeb.Admin do
        pipe_through :browser

        live "/users", UserLive, :index
      end

  the UserLive route would point to the `AppWeb.Admin.UserLive` module

- `Phoenix.View` no longer is needed or included with Phoenix, don't use it
<!-- phoenix:phoenix-end -->

<!-- phoenix:ecto-start -->
## Ecto Guidelines

- **Always** preload Ecto associations in queries when they'll be accessed in templates, ie a message that needs to reference the `message.user.email`
- Remember `import Ecto.Query` and other supporting modules when you write `seeds.exs`
- `Ecto.Schema` fields always use the `:string` type, even for `:text`, columns, ie: `field :name, :string`
- `Ecto.Changeset.validate_number/2` **DOES NOT SUPPORT the `:allow_nil` option**. By default, Ecto validations only run if a change for the given field exists and the change value is not nil, so such as option is never needed
- You **must** use `Ecto.Changeset.get_field(changeset, :field)` to access changeset fields
- Fields which are set programatically, such as `user_id`, must not be listed in `cast` calls or similar for security purposes. Instead they must be explicitly set when creating the struct
<!-- phoenix:ecto-end -->

<!-- phoenix:html-start -->
## Phoenix HTML guidelines

- Phoenix templates **always** use `~H` or .html.heex files (known as HEEx), **never** use `~E`
- **Always** use the imported `Phoenix.Component.form/1` and `Phoenix.Component.inputs_for/1` function to build forms. **Never** use `Phoenix.HTML.form_for` or `Phoenix.HTML.inputs_for` as they are outdated
- When building forms **always** use the already imported `Phoenix.Component.to_form/2` (`assign(socket, form: to_form(...))` and `<.form for={@form} id="msg-form">`), then access those forms in the template via `@form[:field]`
- **Always** add unique DOM IDs to key elements (like forms, buttons, etc) when writing templates, these IDs can later be used in tests (`<.form for={@form} id="product-form">`)
- For "app wide" template imports, you can import/alias into the `my_app_web.ex`'s `html_helpers` block, so they will be available to all LiveViews, LiveComponent's, and all modules that do `use MyAppWeb, :html` (replace "my_app" by the actual app name)

- Elixir supports `if/else` but **does NOT support `if/else if` or `if/elsif`. **Never use `else if` or `elseif` in Elixir**, **always** use `cond` or `case` for multiple conditionals.

  **Never do this (invalid)**:

      <%= if condition do %>
        ...
      <% else if other_condition %>
        ...
      <% end %>

  Instead **always** do this:

      <%= cond do %>
        <% condition -> %>
          ...
        <% condition2 -> %>
          ...
        <% true -> %>
          ...
      <% end %>

- HEEx require special tag annotation if you want to insert literal curly's like `{` or `}`. If you want to show a textual code snippet on the page in a `<pre>` or `<code>` block you *must* annotate the parent tag with `phx-no-curly-interpolation`:

      <code phx-no-curly-interpolation>
        let obj = {key: "val"}
      </code>

  Within `phx-no-curly-interpolation` annotated tags, you can use `{` and `}` without escaping them, and dynamic Elixir expressions can still be used with `<%= ... %>` syntax

- HEEx class attrs support lists, but you must **always** use list `[...]` syntax. You can use the class list syntax to conditionally add classes, **always do this for multiple class values**:

      <a class={[
        "px-2 text-white",
        @some_flag && "py-5",
        if(@other_condition, do: "border-red-500", else: "border-blue-100"),
        ...
      ]}>Text</a>

  and **always** wrap `if`'s inside `{...}` expressions with parens, like done above (`if(@other_condition, do: "...", else: "...")`)

  and **never** do this, since it's invalid (note the missing `[` and `]`):

      <a class={
        "px-2 text-white",
        @some_flag && "py-5"
      }> ...
      => Raises compile syntax error on invalid HEEx attr syntax

- **Never** use `<% Enum.each %>` or non-for comprehensions for generating template content, instead **always** use `<%= for item <- @collection do %>`
- HEEx HTML comments use `<%!-- comment --%>`. **Always** use the HEEx HTML comment syntax for template comments (`<%!-- comment --%>`)
- HEEx allows interpolation via `{...}` and `<%= ... %>`, but the `<%= %>` **only** works within tag bodies. **Always** use the `{...}` syntax for interpolation within tag attributes, and for interpolation of values within tag bodies. **Always** interpolate block constructs (if, cond, case, for) within tag bodies using `<%= ... %>`.

  **Always** do this:

      <div id={@id}>
        {@my_assign}
        <%= if @some_block_condition do %>
          {@another_assign}
        <% end %>
      </div>

  and **Never** do this – the program will terminate with a syntax error:

      <%!-- THIS IS INVALID NEVER EVER DO THIS --%>
      <div id="<%= @invalid_interpolation %>">
        {if @invalid_block_construct do}
        {end}
      </div>
<!-- phoenix:html-end -->

<!-- phoenix:liveview-start -->
## Phoenix LiveView guidelines

- **Never** use the deprecated `live_redirect` and `live_patch` functions, instead **always** use the `<.link navigate={href}>` and  `<.link patch={href}>` in templates, and `push_navigate` and `push_patch` functions LiveViews
- **Avoid LiveComponent's** unless you have a strong, specific need for them
- LiveViews should be named like `AppWeb.WeatherLive`, with a `Live` suffix. When you go to add LiveView routes to the router, the default `:browser` scope is **already aliased** with the `AppWeb` module, so you can just do `live "/weather", WeatherLive`
- Remember anytime you use `phx-hook="MyHook"` and that js hook manages its own DOM, you **must** also set the `phx-update="ignore"` attribute
- **Never** write embedded `<script>` tags in HEEx. Instead always write your scripts and hooks in the `assets/js` directory and integrate them with the `assets/js/app.js` file

### LiveView streams

- **Always** use LiveView streams for collections for assigning regular lists to avoid memory ballooning and runtime termination with the following operations:
  - basic append of N items - `stream(socket, :messages, [new_msg])`
  - resetting stream with new items - `stream(socket, :messages, [new_msg], reset: true)` (e.g. for filtering items)
  - prepend to stream - `stream(socket, :messages, [new_msg], at: -1)`
  - deleting items - `stream_delete(socket, :messages, msg)`

- When using the `stream/3` interfaces in the LiveView, the LiveView template must 1) always set `phx-update="stream"` on the parent element, with a DOM id on the parent element like `id="messages"` and 2) consume the `@streams.stream_name` collection and use the id as the DOM id for each child. For a call like `stream(socket, :messages, [new_msg])` in the LiveView, the template would be:

      <div id="messages" phx-update="stream">
        <div :for={{id, msg} <- @streams.messages} id={id}>
          {msg.text}
        </div>
      </div>

- LiveView streams are *not* enumerable, so you cannot use `Enum.filter/2` or `Enum.reject/2` on them. Instead, if you want to filter, prune, or refresh a list of items on the UI, you **must refetch the data and re-stream the entire stream collection, passing reset: true**:

      def handle_event("filter", %{"filter" => filter}, socket) do
        # re-fetch the messages based on the filter
        messages = list_messages(filter)

        {:noreply,
        socket
        |> assign(:messages_empty?, messages == [])
        # reset the stream with the new messages
        |> stream(:messages, messages, reset: true)}
      end

- LiveView streams *do not support counting or empty states*. If you need to display a count, you must track it using a separate assign. For empty states, you can use Bootstrap utility classes:

      <div id="tasks" phx-update="stream">
        <div class="d-none only:d-block">No tasks yet</div>
        <div :for={{id, task} <- @stream.tasks} id={id}>
          {task.name}
        </div>
      </div>

  The above only works if the empty state is the only HTML block alongside the stream for-comprehension.

- **Never** use the deprecated `phx-update="append"` or `phx-update="prepend"` for collections

### LiveView tests

- `Phoenix.LiveViewTest` module and `LazyHTML` (included) for making your assertions
- Form tests are driven by `Phoenix.LiveViewTest`'s `render_submit/2` and `render_change/2` functions
- Come up with a step-by-step test plan that splits major test cases into small, isolated files. You may start with simpler tests that verify content exists, gradually add interaction tests
- **Always reference the key element IDs you added in the LiveView templates in your tests** for `Phoenix.LiveViewTest` functions like `element/2`, `has_element/2`, selectors, etc
- **Never** tests again raw HTML, **always** use `element/2`, `has_element/2`, and similar: `assert has_element?(view, "#my-form")`
- Instead of relying on testing text content, which can change, favor testing for the presence of key elements
- Focus on testing outcomes rather than implementation details
- Be aware that `Phoenix.Component` functions like `<.form>` might produce different HTML than expected. Test against the output HTML structure, not your mental model of what you expect it to be
- When facing test failures with element selectors, add debug statements to print the actual HTML, but use `LazyHTML` selectors to limit the output, ie:

      html = render(view)
      document = LazyHTML.from_fragment(html)
      matches = LazyHTML.filter(document, "your-complex-selector")
      IO.inspect(matches, label: "Matches")

### Form handling

#### Creating a form from params

If you want to create a form based on `handle_event` params:

    def handle_event("submitted", params, socket) do
      {:noreply, assign(socket, form: to_form(params))}
    end

When you pass a map to `to_form/1`, it assumes said map contains the form params, which are expected to have string keys.

You can also specify a name to nest the params:

    def handle_event("submitted", %{"user" => user_params}, socket) do
      {:noreply, assign(socket, form: to_form(user_params, as: :user))}
    end

#### Creating a form from changesets

When using changesets, the underlying data, form params, and errors are retrieved from it. The `:as` option is automatically computed too. E.g. if you have a user schema:

    defmodule MyApp.Users.User do
      use Ecto.Schema
      ...
    end

And then you create a changeset that you pass to `to_form`:

    %MyApp.Users.User{}
    |> Ecto.Changeset.change()
    |> to_form()

Once the form is submitted, the params will be available under `%{"user" => user_params}`.

In the template, the form form assign can be passed to the `<.form>` function component:

    <.form for={@form} id="todo-form" phx-change="validate" phx-submit="save">
      <.input field={@form[:field]} type="text" />
    </.form>

Always give the form an explicit, unique DOM ID, like `id="todo-form"`.

#### Avoiding form errors

**Always** use a form assigned via `to_form/2` in the LiveView, and the `<.input>` component in the template. In the template **always access forms this**:

    <%!-- ALWAYS do this (valid) --%>
    <.form for={@form} id="my-form">
      <.input field={@form[:field]} type="text" />
    </.form>

And **never** do this:

    <%!-- NEVER do this (invalid) --%>
    <.form for={@changeset} id="my-form">
      <.input field={@changeset[:field]} type="text" />
    </.form>

- You are FORBIDDEN from accessing the changeset in the template as it will cause errors
- **Never** use `<.form let={f} ...>` in the template, instead **always use `<.form for={@form} ...>`**, then drive all form references from the form assign as in `@form[:field]`. The UI should **always** be driven by a `to_form/2` assigned in the LiveView module that is derived from a changeset
<!-- phoenix:liveview-end -->

## Authify Task Framework

Authify uses a comprehensive task framework built on Oban for async job processing with state tracking, retries, exclusivity, and full observability. The framework supports three types of tasks:

### 1. Normal Tasks (BasicTask)

Direct task execution for async operations like sending emails, processing data, etc.

**Architecture:**
```
Code → Tasks.create_and_enqueue_task → TaskExecutor → Task Handler
```

**Creating a task handler:**

```elixir
# lib/authify/tasks/send_welcome_email.ex
defmodule Authify.Tasks.SendWelcomeEmail do
  @moduledoc """
  Sends welcome email to new users.

  Expects params:
  - "user_id" - ID of the user to email
  """
  use Authify.Tasks.BasicTask

  require Logger
  alias Authify.{Accounts, Email}

  @impl true
  def execute(task) do
    user_id = task.params["user_id"]
    user = Accounts.get_user!(user_id)

    case Email.send_welcome_email(user) do
      {:ok, metadata} ->
        Logger.info("Welcome email sent to #{user.email}")
        {:ok, %{sent_at: DateTime.utc_now(), metadata: metadata}}

      {:error, reason} ->
        Logger.error("Failed to send welcome email: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @impl true
  def max_retries, do: 3

  @impl true
  def retry_strategy, do: :exponential
end
```

**Triggering the task:**

```elixir
# In your controller or context
case Tasks.create_and_enqueue_task(%{
       type: "send_welcome_email",
       action: "execute",
       params: %{"user_id" => user.id},
       organization_id: user.organization_id,
       timeout_seconds: 30
     }) do
  {:ok, task} ->
    Logger.info("Email task created: #{task.id}")

  {:error, changeset} ->
    Logger.error("Failed to create task: #{inspect(changeset.errors)}")
end
```

**Important BasicTask behaviors to override:**

- `execute/1` - **Required**. The main task logic. Return `{:ok, results}` or `{:error, reason}`
- `max_retries/0` - Default: 0. Return integer for retry count
- `retry_strategy/0` - Default: `:exponential`. Options: `:exponential`, `:linear`, `:fibonacci`
- `should_retry?/1` - Default: true. Return false to skip retrying specific errors
- `on_success/2` - Hook after successful completion. Can return `{:schedule_task, params}` to chain tasks
- `on_failure/2` - Hook after final failure. Can return `{:schedule_task, params}` for compensation
- `on_retry/3` - Hook before each retry attempt
- `as_comparable_task/1` - Return string key for exclusivity checking, or `nil` to disable
- `comparable_tasks/1` - Override to customize the exclusivity query (e.g., for nil organization_id)
- `on_duplicate/2` - Return `:skip`, `:wait`, `:error`, or `:proceed` when duplicate found

**Exclusivity Pattern for Global Tasks:**

When `organization_id` is `nil` (global tasks), you **must** override `comparable_tasks/1` to avoid Ecto errors:

```elixir
@impl true
def comparable_tasks(task) do
  non_terminal = Task.non_terminal_states()

  from(t in Task,
    where: t.type == ^task.type,
    where: t.action == ^task.action,
    where: is_nil(t.organization_id),  # Important for global tasks!
    where: t.status in ^non_terminal,
    where: t.id != ^task.id
  )
end
```

### 2. Event-Driven Tasks (EventHandler)

Tasks triggered by domain events, providing decoupled orchestration and enabling event-driven architecture.

**Architecture:**
```
Domain Code → EventHandler.handle_event → Creates Event Task → Event Handler → Creates Child Tasks
```

**Creating an event handler:**

```elixir
# lib/authify/tasks/event/user_registered.ex
defmodule Authify.Tasks.Event.UserRegistered do
  @moduledoc """
  Handles user registration events by orchestrating welcome workflow.
  """
  use Authify.Tasks.EventHandler

  alias Authify.Tasks

  @impl true
  def execute(task) do
    user_id = task.params["user_id"]

    # Orchestrate multiple child tasks
    welcome_email_task = %{
      type: "send_welcome_email",
      action: "execute",
      params: %{"user_id" => user_id},
      organization_id: task.organization_id,
      parent_id: task.id
    }

    case Tasks.create_and_enqueue_task(welcome_email_task) do
      {:ok, child_task} ->
        {:ok, %{child_tasks: [child_task.id]}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
```

**Registering the event:**

```elixir
# lib/authify/tasks/event_handler.ex - Add to @event_tasks map
@event_tasks %{
  # ... existing events
  user_registered: Authify.Tasks.Event.UserRegistered
}
```

**Emitting the event:**

```elixir
# In your context after creating a user
def create_user(attrs) do
  Multi.new()
  |> Multi.insert(:user, User.changeset(%User{}, attrs))
  |> Multi.run(:emit_event, fn _repo, %{user: user} ->
    EventHandler.handle_event(:user_registered, %{
      user_id: user.id,
      organization_id: user.organization_id
    })
  end)
  |> Repo.transaction()
end
```

**Key event handler patterns:**

- Event handlers orchestrate workflows by creating child tasks
- Use `parent_id` to track task relationships
- Use `correlation_id` to track related tasks across workflows
- Event tasks always have `type: "event"` and `action: "<event_name>"`
- Keep event handlers thin - delegate work to child tasks

### 3. Scheduled Tasks (Oban Cron)

Recurring maintenance tasks triggered by cron schedules, using a thin wrapper pattern.

**Architecture:**
```
Oban Cron → Scheduled Worker → create_and_enqueue_task → Task Handler
  (timing)    (thin wrapper)      (task framework)         (execution)
```

**Creating a scheduled task:**

**Step 1: Add cron schedule to config/config.exs:**

```elixir
config :authify, Oban,
  # ... other config
  plugins: [
    {Oban.Plugins.Cron,
     crontab: [
       {"0 2 * * *", Authify.Tasks.Workers.Scheduled.CleanupExpiredInvitations},
       {"0 3 * * *", Authify.Tasks.Workers.Scheduled.YourNewTask}
     ]}
  ]
```

**Step 2: Create the scheduled worker (thin wrapper):**

```elixir
# lib/authify/tasks/workers/scheduled/cleanup_expired_invitations.ex
defmodule Authify.Tasks.Workers.Scheduled.CleanupExpiredInvitations do
  @moduledoc """
  Scheduled Oban worker that runs daily to cleanup expired invitations.
  Thin wrapper that creates and enqueues a task in the task framework.
  Runs daily at 2 AM UTC via Oban Cron.
  """
  use Oban.Worker, queue: :scheduled

  require Logger
  alias Authify.Tasks

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    Logger.info("Scheduled job triggered: cleanup_expired_invitations")

    case Tasks.create_and_enqueue_task(%{
           type: "cleanup_expired_invitations",
           action: "execute",
           organization_id: nil,  # Global maintenance task
           status: :pending,
           metadata: %{
             scheduled_by: "oban_cron",
             scheduled_at: DateTime.utc_now()
           }
         }) do
      {:ok, task} ->
        Logger.info("Created and enqueued cleanup task #{task.id}")
        :ok

      {:error, changeset} ->
        Logger.error("Failed to create cleanup task: #{inspect(changeset.errors)}")
        {:error, "Failed to create task"}
    end
  end
end
```

**Step 3: Create the task handler (business logic):**

```elixir
# lib/authify/tasks/cleanup_expired_invitations.ex
defmodule Authify.Tasks.CleanupExpiredInvitations do
  @moduledoc """
  Maintenance task that removes old expired invitations.
  """
  use Authify.Tasks.BasicTask

  require Logger
  alias Authify.Accounts.Invitation
  alias Authify.Repo
  import Ecto.Query

  @impl true
  def execute(_task) do
    Logger.info("Starting cleanup of expired invitations")

    cutoff = DateTime.utc_now() |> DateTime.add(-48, :hour)

    deleted_count =
      from(i in Invitation,
        where: is_nil(i.accepted_at),
        where: i.expires_at < ^cutoff
      )
      |> Repo.delete_all()
      |> elem(0)

    Logger.info("Cleaned up #{deleted_count} expired invitation(s)")
    {:ok, %{deleted_count: deleted_count, cutoff: cutoff}}
  end

  # Override for global tasks (organization_id: nil)
  @impl true
  def comparable_tasks(task) do
    non_terminal = Task.non_terminal_states()

    from(t in Task,
      where: t.type == ^task.type,
      where: t.action == ^task.action,
      where: is_nil(t.organization_id),
      where: t.status in ^non_terminal,
      where: t.id != ^task.id
    )
  end

  @impl true
  def as_comparable_task(_task) do
    "cleanup_expired_invitations:singleton"
  end

  @impl true
  def on_duplicate(_existing, _current), do: :skip
end
```

**Cron syntax reference:**
- `"0 * * * *"` - Every hour
- `"0 2 * * *"` - Daily at 2 AM UTC
- `"0 0 * * 0"` - Weekly on Sunday at midnight
- `"0 0 1 * *"` - Monthly on the 1st at midnight

**Full documentation:** `lib/authify/tasks/workers/scheduled/README.md`

### Task Framework Key Concepts

**State Machine:**
Tasks progress through states: `pending` → `running` → `completing` → `completed`

Active states: `:scheduled`, `:pending`, `:running`, `:waiting`, `:retrying`
Transitioning states: `:completing`, `:failing`, `:expiring`, `:cancelling`, `:timing_out`, `:skipping`
Terminal states: `:completed`, `:failed`, `:expired`, `:timed_out`, `:cancelled`, `:skipped`

**Task Fields:**
- `type` - Handler module name (snake_case), e.g., `"send_invitation"`
- `action` - Usually `"execute"` for tasks, event name for event handlers
- `params` - Map of task parameters (keys are sorted for idempotency)
- `organization_id` - Organization scope, or `nil` for global tasks
- `parent_id` - Links child tasks to parent
- `correlation_id` - Groups related tasks across workflows
- `scheduled_at` - For delayed execution
- `timeout_seconds` - Execution timeout
- `max_retries` / `retry_count` - Retry configuration
- `results` - Output from successful execution
- `errors` - Map of error attempts
- `metadata` - Arbitrary tracking data

**Creating Tasks - IMPORTANT:**

**Always use `Tasks.create_and_enqueue_task/1`** - This is the primary public API.

**Never use `Tasks.create_task/1` directly** - This is a lower-level function only used internally by TaskExecutor for follow-up tasks where it needs to modify attributes before scheduling.

**Task Exclusivity:**

Tasks use a two-phase exclusivity check to prevent duplicates:
1. **Phase 1**: `comparable_tasks/1` - Returns query to filter candidate duplicates (indexed columns)
2. **Phase 2**: `as_comparable_task/1` - Returns string key for exact matching

Return `nil` from `as_comparable_task/1` to disable exclusivity checking.

**Testing Tasks:**

```elixir
use Authify.DataCase, async: false
use Oban.Testing, repo: Authify.Repo

test "executes cleanup task" do
  task = %Authify.Tasks.Task{
    type: "cleanup_expired_invitations",
    action: "execute",
    params: %{}
  }

  assert {:ok, results} = CleanupExpiredInvitations.execute(task)
  assert results.deleted_count >= 0
end

test "scheduled worker creates task" do
  Oban.Testing.with_testing_mode(:manual, fn ->
    job = %Oban.Job{args: %{}}
    assert :ok = CleanupExpiredInvitations.perform(job)

    # Verify task was enqueued
    assert_enqueued(worker: TaskExecutor, args: %{"task_id" => _})
  end)
end
```

**Admin UI:**

Tasks are viewable in:
- Organization-scoped: `/[org-slug]/tasks`
- Global admin: `/authify-global/tasks`

**Best Practices:**

1. **Use the right task type:**
   - Direct async work → BasicTask
   - Domain events → EventHandler
   - Recurring maintenance → Scheduled (Cron)

2. **Keep tasks idempotent** - Tasks may retry, so ensure they can run multiple times safely

3. **Use exclusivity wisely** - Prevent duplicate work with `as_comparable_task/1`

4. **Log appropriately** - Tasks track results and errors, but add Logger for debugging

5. **Set reasonable timeouts** - Default is no timeout; add `timeout_seconds` for long operations

6. **Handle errors gracefully** - Return `{:error, reason}` with descriptive error maps

7. **Chain tasks via hooks** - Use `on_success/2` to return `{:schedule_task, params}` for workflows

8. **Track relationships** - Use `parent_id` and `correlation_id` for task trees and workflows

9. **Test thoroughly** - Write tests for handlers, workers, and integration scenarios

10. **Document params** - Always document expected params in the module docstring

<!-- usage-rules-end -->
