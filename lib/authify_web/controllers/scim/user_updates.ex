defmodule AuthifyWeb.SCIM.UserUpdates do
  @moduledoc """
  Shared SCIM user update helpers for full-replacement (`PUT`) requests.

  SCIM `PUT` replaces a resource's attributes (RFC 7644 Section 3.5.1).
  Authify applies it leniently for omitted attributes, which the RFC permits
  ("the service provider MAY assume that any existing values are to be
  cleared, or the service provider MAY assign a default value") and which
  other service providers such as PingDirectory document ("unspecified
  attributes are ignored"). Attributes that are provided are replaced;
  attributes that are omitted are left as-is. Clients clear a value by sending
  `null` (single-valued) or `[]` (multi-valued); an empty `emails` collection
  is rejected because a user must keep at least one address.

  The user's `emails` collection is a multi-valued association rather than a
  plain field, so it is not applied by
  `Authify.SCIM.Provisioning.update_user_scim/2`. These helpers apply the email
  part of a SCIM `PUT` after the scalar attributes have been updated.
  """

  alias Authify.SCIM.Provisioning

  @doc """
  Applies the email portion of a SCIM `PUT` request to `user`.

  - If the request supplied an `emails` collection, it replaces the user's
    email addresses.
  - Otherwise, if `userName` is an email address, the primary email's value is
    updated in place while other addresses are preserved. This mirrors how user
    creation maps an email-like `userName`.
  - Otherwise the email collection is left untouched.

  `attrs` is the mapped attribute map produced by
  `AuthifyWeb.SCIM.Mappers.map_user_attrs/1`.

  Returns `{:ok, user}` or `{:error, reason}` (reason may be an
  `Ecto.Changeset`).
  """
  def apply_scim_emails(user, params, attrs) do
    cond do
      Map.has_key?(params, "emails") ->
        Provisioning.update_user_emails_scim(user, attrs[:emails] || [])

      email_like_user_name?(params["userName"]) ->
        Provisioning.update_primary_email_scim(user, params["userName"])

      true ->
        {:ok, user}
    end
  end

  @doc """
  Returns true when a SCIM `userName` value looks like an email address.

  ## Examples

      iex> AuthifyWeb.SCIM.UserUpdates.email_like_user_name?("bjensen@example.com")
      true

      iex> AuthifyWeb.SCIM.UserUpdates.email_like_user_name?("bjensen")
      false
  """
  def email_like_user_name?(user_name) when is_binary(user_name) do
    String.contains?(user_name, "@")
  end

  def email_like_user_name?(_user_name), do: false
end
