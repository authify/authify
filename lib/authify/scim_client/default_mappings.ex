defmodule Authify.SCIMClient.DefaultMappings do
  @moduledoc """
  Provider-specific default attribute mappings for common SCIM providers.
  Returns mapping templates as Elixir maps (not JSON strings).
  """

  @doc """
  Gets the default mapping for a given provider type.
  Returns a map with "user" and "group" keys containing SCIM templates.
  """
  def get_default_mapping(provider_type \\ :generic) do
    case provider_type do
      :generic -> generic_mapping()
      :slack -> slack_mapping()
      :github -> github_mapping()
      :okta -> okta_mapping()
      :aws -> aws_mapping()
      _ -> generic_mapping()
    end
  end

  @doc """
  Generic SCIM 2.0 mapping following RFC 7643.
  """
  def generic_mapping do
    %{
      "user" => %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName" => "{{username}}",
        "name" => %{
          "givenName" => "{{first_name}}",
          "familyName" => "{{last_name}}",
          "formatted" => "{{first_name}} {{last_name}}"
        },
        "emails" => [
          %{"value" => "{{primary_email}}", "primary" => true, "type" => "work"}
        ],
        "active" => "{{active}}",
        "externalId" => "{{external_id}}"
      },
      "group" => %{
        "schemas" => ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName" => "{{name}}",
        "externalId" => "{{external_id}}"
      }
    }
  end

  @doc """
  Slack-specific SCIM mapping.
  Slack uses email as userName.
  """
  def slack_mapping do
    generic = generic_mapping()

    %{
      "user" =>
        Map.merge(generic["user"], %{
          "userName" => "{{primary_email}}"
        }),
      "group" => generic["group"]
    }
  end

  @doc """
  GitHub Enterprise SCIM mapping.
  """
  def github_mapping do
    # GitHub uses standard SCIM 2.0
    generic_mapping()
  end

  @doc """
  Okta SCIM mapping.
  """
  def okta_mapping do
    generic = generic_mapping()

    %{
      "user" =>
        Map.merge(generic["user"], %{
          "schemas" => [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
          ]
        }),
      "group" => generic["group"]
    }
  end

  @doc """
  AWS SSO SCIM mapping.
  """
  def aws_mapping do
    generic = generic_mapping()

    %{
      "user" =>
        Map.merge(generic["user"], %{
          "displayName" => "{{first_name}} {{last_name}}"
        }),
      "group" => generic["group"]
    }
  end

  @doc """
  Returns a JSON-encoded default mapping for a given provider.
  """
  def get_default_mapping_json(provider_type \\ :generic) do
    get_default_mapping(provider_type)
    |> Jason.encode!()
  end
end
