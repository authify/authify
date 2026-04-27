defmodule AuthifyTest.SCIMConsumer do
  @moduledoc false

  @endpoint AuthifyWeb.Endpoint

  import Plug.Conn, only: [get_resp_header: 2, put_req_header: 3]
  import Phoenix.ConnTest

  defstruct [:conn, :org, :token]

  def new(conn, org, opts) do
    %__MODULE__{conn: conn, org: org, token: Keyword.fetch!(opts, :token)}
  end

  # ── User Lifecycle ─────────────────────────────────────────

  def create_user(%__MODULE__{} = consumer, attrs) do
    body =
      Enum.into(attrs, %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"]
      })

    resp = request(consumer, :post, "/Users", body: body)

    case resp do
      {:ok, conn} ->
        with :ok <- cache_etag(consumer, "Users", id_from(resp), conn) do
          handle_response(resp, :resource)
        end

      err ->
        handle_response(err, :resource)
    end
  end

  def fetch_user(%__MODULE__{} = consumer, id) do
    resp = request(consumer, :get, "/Users/#{id}")
    handle_response(resp, :resource)
  end

  def update_user(%__MODULE__{} = consumer, id, attrs) do
    headers = if_etag_cached(consumer, "Users", id)

    resp =
      request(consumer, :put, "/Users/#{id}",
        body: Enum.into(attrs, %{}),
        headers: headers
      )

    case resp do
      {:ok, conn} ->
        with :ok <- cache_etag(consumer, "Users", id, conn) do
          handle_response(resp, :resource)
        end

      err ->
        handle_response(err, :resource)
    end
  end

  def patch_user(%__MODULE__{} = consumer, id, operations) do
    headers = if_etag_cached(consumer, "Users", id)

    body = %{
      "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      "Operations" => operations
    }

    resp =
      request(consumer, :patch, "/Users/#{id}",
        body: body,
        headers: headers
      )

    case resp do
      {:ok, conn} ->
        with :ok <- cache_etag(consumer, "Users", id, conn) do
          handle_response(resp, :resource)
        end

      err ->
        handle_response(err, :resource)
    end
  end

  def delete_user(%__MODULE__{} = consumer, id) do
    resp = request(consumer, :delete, "/Users/#{id}")
    handle_response(resp, :deletion)
  end

  def list_users(%__MODULE__{} = consumer, opts \\ []) do
    query = build_list_query(opts)
    resp = request(consumer, :get, "/Users", query: query)
    handle_response(resp, :list)
  end

  # ── Group Lifecycle ─────────────────────────────────────

  def create_group(%__MODULE__{} = consumer, display_name, opts \\ []) do
    body =
      Enum.into(opts, %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName" => display_name
      })

    resp = request(consumer, :post, "/Groups", body: body)

    case resp do
      {:ok, conn} ->
        with :ok <- cache_etag(consumer, "Groups", id_from(resp), conn) do
          handle_response(resp, :resource)
        end

      err ->
        handle_response(err, :resource)
    end
  end

  def update_group_members(%__MODULE__{} = consumer, group_id, opts) do
    add = Keyword.get(opts, :add, [])
    remove = Keyword.get(opts, :remove, [])

    operations =
      for(id <- add, do: %{"op" => "add", "path" => "members", "value" => [%{"value" => id}]}) ++
        for id <- remove, do: %{"op" => "remove", "path" => "members[value eq \"#{id}\"]"}

    headers = if_etag_cached(consumer, "Groups", group_id)

    body = %{
      "schemas" => ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      "Operations" => operations
    }

    resp =
      request(consumer, :patch, "/Groups/#{group_id}",
        body: body,
        headers: headers
      )

    case resp do
      {:ok, conn} ->
        with :ok <- cache_etag(consumer, "Groups", group_id, conn) do
          handle_response(resp, :resource)
        end

      err ->
        handle_response(err, :resource)
    end
  end

  def list_groups(%__MODULE__{} = consumer, opts \\ []) do
    query = build_list_query(opts)
    resp = request(consumer, :get, "/Groups", query: query)
    handle_response(resp, :list)
  end

  # ── Response Validation ─────────────────────────────────

  def validate_resource(resource) when is_map(resource) do
    schemas = Map.get(resource, "schemas")
    id = Map.get(resource, "id")
    meta = Map.get(resource, "meta")

    missing =
      if(is_nil(schemas) or (is_list(schemas) and Enum.empty?(schemas)),
        do: ["schemas"],
        else: []
      ) ++
        if(is_nil(id), do: ["id"], else: []) ++
        if is_nil(meta), do: ["meta.resourceType", "meta.location"], else: valid_meta_keys(meta)

    if Enum.empty?(missing), do: {:ok, resource}, else: {:error, {:invalid_response, missing}}
  end

  def validate_list_response(response) when is_map(response) do
    missing =
      if(is_nil(Map.get(response, "totalResults")), do: ["totalResults"], else: []) ++
        if(is_nil(Map.get(response, "startIndex")), do: ["startIndex"], else: []) ++
        if(is_nil(Map.get(response, "itemsPerPage")), do: ["itemsPerPage"], else: []) ++
        if is_nil(Map.get(response, "Resources")), do: ["Resources"], else: []

    if Enum.empty?(missing), do: {:ok, response}, else: {:error, {:invalid_response, missing}}
  end

  # ── Private Helpers ───────────────────────────────────

  defp request(consumer, method, path, opts \\ []) do
    url = "/#{consumer.org.slug}/scim/v2#{path}"

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer #{consumer.token}")

    conn =
      if method in [:post, :put, :patch] do
        put_req_header(conn, "content-type", "application/scim+json")
      else
        conn
      end

    conn =
      if opts[:headers] do
        Enum.reduce(opts[:headers], conn, fn {k, v}, c ->
          put_req_header(c, String.downcase(k), v)
        end)
      else
        conn
      end

    resp =
      case method do
        :get -> get(conn, url, opts[:query])
        :post -> post(conn, url, opts[:body])
        :put -> put(conn, url, opts[:body])
        :patch -> patch(conn, url, opts[:body])
        :delete -> delete(conn, url, opts[:query])
      end

    status = resp.status

    if status in [200, 201, 204] do
      {:ok, resp}
    else
      {:error, {conn, resp}}
    end
  end

  defp if_etag_cached(consumer, type, id) do
    case cached_etag(consumer, type, id) do
      nil -> []
      etag -> [{"if-match", etag}]
    end
  end

  defp cache_etag(consumer, type, id, resp_conn) do
    case get_resp_header(resp_conn, "etag") |> List.first() do
      nil ->
        :ok

      etag ->
        Process.put({:scim_etag, consumer.org.id, type, id}, etag)
        :ok
    end
  end

  defp cached_etag(consumer, type, id) do
    Process.get({:scim_etag, consumer.org.id, type, id})
  end

  defp handle_response({:error, {_conn, resp}}, _type) do
    body = resp.resp_body |> Jason.decode!()

    case resp.status do
      404 -> {:error, :not_found}
      403 -> {:error, :forbidden}
      409 -> {:error, :conflict}
      412 -> {:error, :conflict}
      _ -> {:error, {:unexpected_status, resp.status, body}}
    end
  end

  defp handle_response({:ok, resp}, :resource) do
    body = resp.resp_body |> Jason.decode!()
    validate_resource(body)
  end

  defp handle_response({:ok, resp}, :deletion) do
    if resp.status == 204, do: :ok, else: {:error, {:unexpected_status, resp.status, ""}}
  end

  defp handle_response({:ok, resp}, :list) do
    body = resp.resp_body |> Jason.decode!()
    validate_list_response(body)
  end

  defp build_list_query(opts) do
    params =
      opts
      |> Enum.flat_map(fn
        {:filter, v} -> [{"filter", v}]
        {:count, v} -> [{"count", to_string(v)}]
        {:start_index, v} -> [{"startIndex", to_string(v)}]
        {:sort_by, v} -> [{"sortBy", v}]
        {:sort_order, v} -> [{"sortOrder", v}]
        _ -> []
      end)
      |> Map.new()

    if map_size(params) == 0, do: nil, else: params
  end

  defp valid_meta_keys(meta) when is_map(meta) do
    if(is_nil(Map.get(meta, "resourceType")), do: ["meta.resourceType"], else: []) ++
      if is_nil(Map.get(meta, "location")), do: ["meta.location"], else: []
  end

  defp id_from({:ok, resp}) do
    case get_resp_header(resp, "location") |> List.first() do
      nil -> nil
      loc -> String.split(loc, "/") |> List.last()
    end
  end
end
