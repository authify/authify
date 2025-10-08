defmodule Authify.OAuth.AuthorizationCode do
  use Ecto.Schema
  import Ecto.Changeset

  schema "authorization_codes" do
    field :code, :string
    field :redirect_uri, :string
    field :scopes, :string
    field :expires_at, :utc_datetime
    field :used_at, :utc_datetime
    # PKCE fields
    field :code_challenge, :string
    field :code_challenge_method, :string

    belongs_to :application, Authify.OAuth.Application
    belongs_to :user, Authify.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(authorization_code, attrs) do
    authorization_code
    |> cast(attrs, [
      :code,
      :redirect_uri,
      :scopes,
      :expires_at,
      :used_at,
      :code_challenge,
      :code_challenge_method,
      :application_id,
      :user_id
    ])
    |> validate_required([:redirect_uri, :scopes, :application_id, :user_id])
    |> validate_pkce()
    |> put_code()
    |> put_expires_at()
    |> unique_constraint(:code)
  end

  defp validate_pkce(changeset) do
    code_challenge = get_field(changeset, :code_challenge)
    code_challenge_method = get_field(changeset, :code_challenge_method)

    cond do
      # Both present - validate method
      code_challenge && code_challenge_method ->
        if code_challenge_method in ["S256", "plain"] do
          changeset
        else
          add_error(
            changeset,
            :code_challenge_method,
            "must be S256 or plain"
          )
        end

      # Challenge present but no method - default to plain
      code_challenge && !code_challenge_method ->
        put_change(changeset, :code_challenge_method, "plain")

      # Neither present - no PKCE
      true ->
        changeset
    end
  end

  defp put_code(%Ecto.Changeset{valid?: true} = changeset) do
    put_change(changeset, :code, generate_code())
  end

  defp put_code(changeset), do: changeset

  defp put_expires_at(%Ecto.Changeset{valid?: true} = changeset) do
    case get_change(changeset, :expires_at) do
      nil ->
        expires_at =
          DateTime.utc_now() |> DateTime.add(600, :second) |> DateTime.truncate(:second)

        put_change(changeset, :expires_at, expires_at)

      _existing_expires_at ->
        changeset
    end
  end

  defp put_expires_at(changeset), do: changeset

  defp generate_code do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  def used?(%__MODULE__{used_at: used_at}) do
    not is_nil(used_at)
  end

  def valid_for_exchange?(%__MODULE__{} = auth_code) do
    not expired?(auth_code) and not used?(auth_code)
  end

  def mark_as_used(changeset) do
    put_change(changeset, :used_at, DateTime.utc_now() |> DateTime.truncate(:second))
  end

  def scopes_list(%__MODULE__{scopes: scopes}) when is_binary(scopes) do
    String.split(scopes, " ") |> Enum.reject(&(&1 == ""))
  end

  def scopes_list(_), do: []

  @doc """
  Verifies a PKCE code_verifier against the stored code_challenge.
  Returns true if PKCE is not used or if the verifier is valid.
  """
  def verify_pkce(
        %__MODULE__{code_challenge: nil, code_challenge_method: nil},
        _code_verifier
      ) do
    # No PKCE used, always valid
    true
  end

  def verify_pkce(%__MODULE__{code_challenge: challenge, code_challenge_method: method}, verifier)
      when is_binary(verifier) do
    computed_challenge =
      case method do
        "S256" ->
          :crypto.hash(:sha256, verifier)
          |> Base.url_encode64(padding: false)

        "plain" ->
          verifier

        _ ->
          nil
      end

    computed_challenge == challenge
  end

  def verify_pkce(_, _), do: false
end
