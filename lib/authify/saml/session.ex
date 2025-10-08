defmodule Authify.SAML.Session do
  use Ecto.Schema
  import Ecto.Changeset

  schema "saml_sessions" do
    field :session_id, :string
    field :subject_id, :string
    field :request_id, :string
    field :relay_state, :string
    field :issued_at, :utc_datetime
    field :expires_at, :utc_datetime

    belongs_to :user, Authify.Accounts.User
    belongs_to :service_provider, Authify.SAML.ServiceProvider

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(session, attrs) do
    session
    |> cast(attrs, [
      :session_id,
      :subject_id,
      :request_id,
      :relay_state,
      :issued_at,
      :expires_at,
      :user_id,
      :service_provider_id
    ])
    |> validate_required([
      :session_id,
      :subject_id,
      :issued_at,
      :expires_at,
      :service_provider_id
    ])
    |> maybe_force_user_id_nil(attrs)
    |> put_default_expires_at()
    |> unique_constraint(:session_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:service_provider_id)
  end

  # If user_id is explicitly set to nil in attrs, force it in the changeset
  defp maybe_force_user_id_nil(changeset, %{user_id: nil}) do
    force_change(changeset, :user_id, nil)
  end

  defp maybe_force_user_id_nil(changeset, _attrs), do: changeset

  defp put_default_expires_at(%Ecto.Changeset{valid?: true} = changeset) do
    case get_field(changeset, :expires_at) do
      nil ->
        expires_at =
          DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)

        put_change(changeset, :expires_at, expires_at)

      _ ->
        changeset
    end
  end

  defp put_default_expires_at(changeset), do: changeset

  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  def valid?(%__MODULE__{} = session) do
    not expired?(session)
  end

  def generate_session_id do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  def generate_subject_id(%Authify.Accounts.User{} = user, %Authify.SAML.ServiceProvider{} = sp) do
    # Generate a persistent but opaque subject identifier
    # This could be based on user ID + SP entity ID for consistency
    data = "#{user.id}:#{sp.entity_id}"
    :crypto.hash(:sha256, data) |> Base.hex_encode32(case: :lower)
  end
end
