defmodule Authify.Guardian do
  @moduledoc """
  Guardian module for JWT token handling in Authify.
  """

  use Guardian, otp_app: :authify

  alias Authify.Accounts

  def subject_for_token(%{id: id}, _claims) do
    {:ok, to_string(id)}
  end

  def subject_for_token(_, _) do
    {:error, :reason_for_error}
  end

  # Embed the user's session version in every token so that bumping the version
  # (e.g. when an admin forces a password reset) invalidates all prior tokens.
  def build_claims(claims, %Accounts.User{session_version: version}, _opts)
      when is_integer(version) do
    {:ok, Map.put(claims, "ver", version)}
  end

  def build_claims(claims, _resource, _opts) do
    {:ok, claims}
  end

  # Reject tokens issued before the user's current session version. Older tokens
  # predating this claim have no "ver" and default to version 0.
  def verify_claims(%{"sub" => id} = claims, _opts) do
    case Accounts.get_user(id) do
      %Accounts.User{session_version: current_version} ->
        if Map.get(claims, "ver", 0) == current_version do
          {:ok, claims}
        else
          {:error, :session_revoked}
        end

      nil ->
        {:ok, claims}
    end
  end

  def verify_claims(claims, _opts), do: {:ok, claims}

  def resource_from_claims(%{"sub" => id}) do
    case Accounts.get_user(id) do
      nil -> {:error, :resource_not_found}
      user -> {:ok, user}
    end
  end

  def resource_from_claims(_claims) do
    {:error, :reason_for_error}
  end
end
