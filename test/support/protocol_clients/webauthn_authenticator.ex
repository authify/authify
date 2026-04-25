defmodule AuthifyTest.WebAuthnAuthenticator do
  @moduledoc false

  defstruct [:private_key, :public_key_raw, :credential_id, :sign_count, :aaguid, :user_verified]

  def new(opts \\ []) do
    {public_key_raw, private_key} = :crypto.generate_key(:ecdh, :prime256v1)

    %__MODULE__{
      private_key: private_key,
      public_key_raw: public_key_raw,
      credential_id: :crypto.strong_rand_bytes(16),
      sign_count: 0,
      aaguid: Keyword.get(opts, :aaguid, <<0::128>>),
      user_verified: Keyword.get(opts, :user_verified, true)
    }
  end
end
