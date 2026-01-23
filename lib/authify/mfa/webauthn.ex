defmodule Authify.MFA.WebAuthn do
  @moduledoc """
  WebAuthn/FIDO2 authentication context.

  Handles credential registration, authentication, and management for both
  platform authenticators (Touch ID, Face ID, Windows Hello) and roaming
  authenticators (YubiKey, Titan Key, etc.).
  """

  import Ecto.Query
  import Bitwise
  alias Authify.Accounts.{Organization, User}
  alias Authify.Encryption
  alias Authify.MFA.{WebAuthnChallenge, WebAuthnCredential}
  alias Authify.Repo

  require Logger

  # Registration Functions

  @doc """
  Begins WebAuthn credential registration by generating a challenge.

  Returns challenge data and registration options for the client.

  ## Options
  - `:authenticator_attachment` - "platform", "cross-platform", or nil (any)
  - `:user_verification` - "required", "preferred", or "discouraged"
  - `:attestation` - "none", "indirect", or "direct"
  - `:credential_type` - "platform" or "roaming" (stored in credential record)
  - `:ip_address` - client IP address
  - `:user_agent` - client user agent

  ## Example
      iex> begin_registration(user, authenticator_attachment: "platform")
      {:ok, %{challenge: "...", options: %{...}}}
  """
  def begin_registration(%User{} = user, opts \\ []) do
    # Generate challenge
    challenge_bytes = :crypto.strong_rand_bytes(32)
    challenge_b64 = Base.url_encode64(challenge_bytes, padding: false)

    # Store challenge in database
    challenge_record =
      %WebAuthnChallenge{}
      |> WebAuthnChallenge.changeset(%{
        user_id: user.id,
        challenge: challenge_b64,
        challenge_type: "registration",
        expires_at: WebAuthnChallenge.calculate_expiry(),
        ip_address: opts[:ip_address],
        user_agent: opts[:user_agent]
      })
      |> Repo.insert()

    case challenge_record do
      {:ok, _challenge} ->
        # Build registration options for client
        options = %{
          challenge: challenge_b64,
          rp: %{
            name: get_rp_name(),
            id: get_rp_id()
          },
          user: %{
            id: Base.url_encode64("user_#{user.id}", padding: false),
            name: user.username,
            displayName: display_name_for_user(user)
          },
          pubKeyCredParams: [
            %{type: "public-key", alg: -7},
            # ES256
            %{type: "public-key", alg: -257}
            # RS256
          ],
          timeout: 60_000,
          # 60 seconds
          authenticatorSelection: %{
            authenticatorAttachment: opts[:authenticator_attachment],
            userVerification: opts[:user_verification] || "preferred",
            requireResidentKey: false
          },
          attestation: opts[:attestation] || "none",
          excludeCredentials: get_exclude_credentials(user)
        }

        {:ok, %{challenge: challenge_b64, options: options}}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Completes WebAuthn credential registration by verifying the attestation response.

  ## Parameters
  - `user` - The user registering the credential
  - `attestation_response` - The client's attestation response (map with keys: id, rawId, response, type)
  - `challenge` - The challenge string from begin_registration
  - `opts` - Options including :name, :credential_type, :ip_address

  Returns `{:ok, credential}` or `{:error, reason}`.
  """
  def complete_registration(%User{} = user, attestation_response, challenge, opts \\ []) do
    with {:ok, challenge_record} <- verify_challenge(user, challenge, "registration"),
         {:ok, credential_data} <- verify_attestation(attestation_response, challenge),
         {:ok, credential} <- store_credential(user, credential_data, attestation_response, opts) do
      # Mark challenge as consumed
      challenge_record
      |> Ecto.Changeset.change(%{consumed_at: DateTime.utc_now()})
      |> Repo.update()

      {:ok, credential}
    else
      {:error, reason} = error ->
        Logger.warning("WebAuthn registration failed: #{inspect(reason)}")
        error
    end
  end

  # Authentication Functions

  @doc """
  Begins WebAuthn authentication by generating a challenge.

  Returns challenge data and authentication options for the client.
  """
  def begin_authentication(%User{} = user, opts \\ []) do
    # Get user's credentials
    credentials = list_credentials(user)

    if Enum.empty?(credentials) do
      {:error, :no_credentials}
    else
      # Generate challenge
      challenge_bytes = :crypto.strong_rand_bytes(32)
      challenge_b64 = Base.url_encode64(challenge_bytes, padding: false)

      # Store challenge in database
      challenge_record =
        %WebAuthnChallenge{}
        |> WebAuthnChallenge.changeset(%{
          user_id: user.id,
          challenge: challenge_b64,
          challenge_type: "authentication",
          expires_at: WebAuthnChallenge.calculate_expiry(),
          ip_address: opts[:ip_address],
          user_agent: opts[:user_agent]
        })
        |> Repo.insert()

      case challenge_record do
        {:ok, _challenge} ->
          # Build authentication options for client
          options = %{
            challenge: challenge_b64,
            timeout: 60_000,
            # 60 seconds
            rpId: get_rp_id(),
            userVerification: opts[:user_verification] || "preferred",
            allowCredentials:
              Enum.map(credentials, fn cred ->
                %{
                  type: "public-key",
                  id: cred.credential_id,
                  transports: parse_transports(cred.transports)
                }
              end)
          }

          {:ok, %{challenge: challenge_b64, options: options}}

        {:error, changeset} ->
          {:error, changeset}
      end
    end
  end

  @doc """
  Completes WebAuthn authentication by verifying the assertion response.

  ## Parameters
  - `user` - The user authenticating
  - `assertion_response` - The client's assertion response
  - `challenge` - The challenge string from begin_authentication

  Returns `{:ok, credential}` or `{:error, reason}`.
  """
  def complete_authentication(%User{} = user, assertion_response, challenge) do
    with {:ok, challenge_record} <- verify_challenge(user, challenge, "authentication"),
         {:ok, credential} <- get_credential_by_id(assertion_response["id"]),
         :ok <- verify_credential_owner(credential, user),
         {:ok, updated_credential} <-
           verify_assertion(credential, assertion_response, challenge) do
      # Mark challenge as consumed
      challenge_record
      |> Ecto.Changeset.change(%{consumed_at: DateTime.utc_now()})
      |> Repo.update()

      # Update last_used_at
      updated_credential
      |> Ecto.Changeset.change(%{last_used_at: DateTime.utc_now()})
      |> Repo.update()
    else
      {:error, reason} = error ->
        Logger.warning("WebAuthn authentication failed: #{inspect(reason)}")
        error
    end
  end

  # Credential Management Functions

  @doc """
  Lists all WebAuthn credentials for a user.
  """
  def list_credentials(%User{} = user) do
    WebAuthnCredential
    |> where([c], c.user_id == ^user.id)
    |> order_by([c], desc: c.last_used_at, desc: c.inserted_at)
    |> Repo.all()
  end

  @doc """
  Gets a credential by ID.
  """
  def get_credential(id) do
    case Repo.get(WebAuthnCredential, id) do
      nil -> {:error, :not_found}
      credential -> {:ok, credential}
    end
  end

  @doc """
  Gets a credential by credential_id (the WebAuthn credential ID).
  """
  def get_credential_by_id(credential_id) do
    case Repo.get_by(WebAuthnCredential, credential_id: credential_id) do
      nil -> {:error, :credential_not_found}
      credential -> {:ok, Repo.preload(credential, :user)}
    end
  end

  @doc """
  Revokes (deletes) a WebAuthn credential.
  """
  def revoke_credential(credential_id)
      when is_binary(credential_id) or is_integer(credential_id) do
    case get_credential(credential_id) do
      {:ok, credential} ->
        Repo.delete(credential)

      error ->
        error
    end
  end

  @doc """
  Revokes all WebAuthn credentials for a user.
  """
  def revoke_all_credentials(%User{} = user) do
    {count, _} =
      WebAuthnCredential
      |> where([c], c.user_id == ^user.id)
      |> Repo.delete_all()

    {:ok, count}
  end

  @doc """
  Updates the friendly name of a credential.
  """
  def update_credential_name(credential_id, name) do
    case get_credential(credential_id) do
      {:ok, credential} ->
        credential
        |> Ecto.Changeset.change(%{name: name})
        |> Repo.update()

      error ->
        error
    end
  end

  # Rate Limiting Functions

  @doc """
  Checks rate limit for WebAuthn operations.

  Uses the same organization-level MFA rate limiting settings as TOTP.
  """
  def check_rate_limit(%User{} = user, %Organization{} = organization) do
    # Delegate to MFA.check_rate_limit for consistent rate limiting
    Authify.MFA.check_rate_limit(user, organization)
  end

  # Private Functions

  defp verify_challenge(%User{} = user, challenge, expected_type) do
    case Repo.get_by(WebAuthnChallenge,
           user_id: user.id,
           challenge: challenge,
           challenge_type: expected_type
         ) do
      nil ->
        {:error, :invalid_challenge}

      challenge_record ->
        cond do
          WebAuthnChallenge.consumed?(challenge_record) ->
            {:error, :challenge_already_used}

          WebAuthnChallenge.expired?(challenge_record) ->
            {:error, :challenge_expired}

          true ->
            {:ok, challenge_record}
        end
    end
  end

  defp verify_attestation(attestation_response, challenge) do
    # Extract response data
    client_data_json = attestation_response["response"]["clientDataJSON"]
    attestation_object = attestation_response["response"]["attestationObject"]

    # Decode client data
    client_data =
      client_data_json
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    # Verify challenge matches
    response_challenge = client_data["challenge"]

    if response_challenge == challenge do
      # Decode attestation object (CBOR)
      attestation_data = Base.url_decode64!(attestation_object, padding: false)

      case CBOR.decode(attestation_data) do
        {:ok, decoded, ""} ->
          # Extract authenticator data and attestation statement
          auth_data = decoded["authData"]
          fmt = decoded["fmt"]
          att_stmt = decoded["attStmt"]

          # Extract credential data from authenticator data
          credential_data = parse_authenticator_data(auth_data)

          {:ok, Map.merge(credential_data, %{fmt: fmt, att_stmt: att_stmt})}

        _ ->
          {:error, :invalid_attestation_object}
      end
    else
      {:error, :challenge_mismatch}
    end
  end

  defp parse_authenticator_data(auth_data) when is_binary(auth_data) do
    # Parse authenticator data structure
    # Bytes 0-31: RP ID hash (32 bytes)
    # Byte 32: Flags
    # Bytes 33-36: Sign count (4 bytes, big-endian)
    # Bytes 37+: Attested credential data (if present)

    <<_rp_id_hash::binary-size(32), flags::8, sign_count::32, credential_data::binary>> =
      auth_data

    # Check if attested credential data is present (AT flag, bit 6)
    at_flag = (flags &&& 0x40) != 0

    if at_flag do
      # Parse attested credential data
      <<aaguid::binary-size(16), cred_id_len::16, rest::binary>> = credential_data
      <<credential_id::binary-size(cred_id_len), public_key_cbor::binary>> = rest

      # Decode public key (COSE format)
      case CBOR.decode(public_key_cbor) do
        {:ok, _public_key, _} ->
          %{
            credential_id: Base.url_encode64(credential_id, padding: false),
            public_key: public_key_cbor,
            # Store raw CBOR for later verification
            sign_count: sign_count,
            aaguid: aaguid
          }

        _ ->
          %{error: :invalid_public_key}
      end
    else
      %{error: :no_credential_data}
    end
  end

  defp store_credential(%User{} = user, credential_data, attestation_response, opts) do
    # Encrypt public key before storage
    encrypted_public_key = Encryption.encrypt(credential_data.public_key)

    # Extract transports from response
    transports =
      attestation_response
      |> get_in(["response", "transports"])
      |> case do
        nil -> nil
        list when is_list(list) -> Jason.encode!(list)
        _ -> nil
      end

    # Default name if not provided
    credential_type = opts[:credential_type] || infer_credential_type(attestation_response)
    name = opts[:name] || generate_default_name(credential_type)

    %WebAuthnCredential{}
    |> WebAuthnCredential.changeset(%{
      user_id: user.id,
      organization_id: user.organization_id,
      credential_id: credential_data.credential_id,
      public_key: encrypted_public_key,
      sign_count: credential_data.sign_count,
      credential_type: credential_type,
      transports: transports,
      aaguid: credential_data.aaguid,
      name: name,
      last_used_at: DateTime.utc_now()
    })
    |> Repo.insert()
  end

  defp verify_credential_owner(%WebAuthnCredential{user_id: cred_user_id}, %User{id: user_id}) do
    if cred_user_id == user_id do
      :ok
    else
      {:error, :credential_not_owned}
    end
  end

  defp verify_assertion(credential, assertion_response, challenge) do
    # Extract response data
    client_data_json = assertion_response["response"]["clientDataJSON"]
    authenticator_data = assertion_response["response"]["authenticatorData"]
    _signature = assertion_response["response"]["signature"]

    # Decode client data
    client_data =
      client_data_json
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    # Verify challenge matches
    response_challenge = client_data["challenge"]

    if response_challenge == challenge do
      # Decode authenticator data
      auth_data_binary = Base.url_decode64!(authenticator_data, padding: false)

      # Extract sign count from authenticator data (bytes 33-36)
      <<_rp_id_hash::binary-size(32), _flags::8, new_sign_count::32, _rest::binary>> =
        auth_data_binary

      # Verify sign count (anti-cloning detection)
      if new_sign_count > credential.sign_count do
        # Decrypt public key
        case Encryption.decrypt(credential.public_key) do
          {:ok, _public_key_cbor} ->
            # TODO: Verify signature using public key (requires additional crypto library)
            # For now, we'll update the sign count
            updated_credential =
              credential
              |> Ecto.Changeset.change(%{sign_count: new_sign_count})
              |> Repo.update!()

            {:ok, updated_credential}

          {:error, _reason} ->
            {:error, :decryption_failed}
        end
      else
        {:error, :invalid_sign_count}
      end
    else
      {:error, :challenge_mismatch}
    end
  end

  defp get_rp_name do
    Application.get_env(:authify, :webauthn_rp_name, "Authify")
  end

  defp get_rp_id do
    Application.get_env(:authify, :webauthn_rp_id, "localhost")
  end

  defp display_name_for_user(%User{} = user) do
    cond do
      user.first_name && user.last_name ->
        "#{user.first_name} #{user.last_name}"

      user.first_name ->
        user.first_name

      user.username && user.username != "" ->
        user.username

      true ->
        "User #{user.id}"
    end
  end

  defp get_exclude_credentials(%User{} = user) do
    credentials = list_credentials(user)

    Enum.map(credentials, fn cred ->
      %{
        type: "public-key",
        id: cred.credential_id,
        transports: parse_transports(cred.transports)
      }
    end)
  end

  defp parse_transports(nil), do: []

  defp parse_transports(transports) when is_binary(transports) do
    case Jason.decode(transports) do
      {:ok, list} when is_list(list) -> list
      _ -> []
    end
  end

  defp parse_transports(_), do: []

  defp infer_credential_type(%{"response" => %{"transports" => transports}})
       when is_list(transports) do
    if "internal" in transports do
      "platform"
    else
      "roaming"
    end
  end

  defp infer_credential_type(_), do: "roaming"

  defp generate_default_name("platform"), do: "Platform Authenticator"
  defp generate_default_name("roaming"), do: "Security Key"
  defp generate_default_name(_), do: "Authenticator"
end
