defmodule AuthifyWeb.OIDCController do
  use AuthifyWeb, :controller

  alias Authify.SAML

  @doc """
  OIDC Discovery endpoint.
  Returns the OpenID Connect configuration for this provider.
  """
  def discovery(conn, _params) do
    organization = conn.assigns[:current_organization]
    base_url = AuthifyWeb.Endpoint.url()
    org_base_url = "#{base_url}/#{organization.slug}"

    config = %{
      issuer: org_base_url,
      authorization_endpoint: "#{org_base_url}/oauth/authorize",
      token_endpoint: "#{org_base_url}/oauth/token",
      userinfo_endpoint: "#{org_base_url}/oauth/userinfo",
      jwks_uri: "#{org_base_url}/.well-known/jwks",
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "email"],
      claims_supported: [
        "sub",
        "name",
        "preferred_username",
        "email",
        "email_verified",
        "updated_at"
      ],
      grant_types_supported: ["authorization_code"],
      response_modes_supported: ["query"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      code_challenge_methods_supported: ["S256", "plain"]
    }

    json(conn, config)
  end

  @doc """
  JWKS endpoint for public keys.
  Returns the active signing certificate's public key in JWK format.
  """
  def jwks(conn, _params) do
    organization = conn.assigns[:current_organization]

    case SAML.get_active_certificate(organization, "signing") do
      nil ->
        # No active certificate, return empty keyset
        json(conn, %{keys: []})

      certificate ->
        jwk = convert_certificate_to_jwk(certificate)
        json(conn, %{keys: [jwk]})
    end
  end

  # Convert an RSA certificate to JWK format
  defp convert_certificate_to_jwk(certificate) do
    # Parse the PEM-encoded certificate
    [{:Certificate, der_cert, _}] = :public_key.pem_decode(certificate.certificate)
    otp_cert = :public_key.pkix_decode_cert(der_cert, :otp)

    # Extract the public key from OTP certificate tuple structure
    # OTPCertificate is {:OTPCertificate, tbs_certificate, signature_algorithm, signature}
    tbs_certificate = elem(otp_cert, 1)

    # OTPTBSCertificate structure - field 8 is subjectPublicKeyInfo (0-indexed, so position 7)
    subject_public_key_info = elem(tbs_certificate, 7)

    # OTPSubjectPublicKeyInfo is {:OTPSubjectPublicKeyInfo, algorithm, public_key}
    public_key = elem(subject_public_key_info, 2)

    # RSA public key is a tuple {:RSAPublicKey, modulus, exponent}
    {modulus, exponent} = {elem(public_key, 1), elem(public_key, 2)}

    # Convert to JWK format
    %{
      kty: "RSA",
      use: "sig",
      kid: to_string(certificate.id),
      n: Base.url_encode64(int_to_binary(modulus), padding: false),
      e: Base.url_encode64(int_to_binary(exponent), padding: false),
      alg: "RS256"
    }
  end

  # Convert an integer to binary representation
  defp int_to_binary(int) when is_integer(int) do
    # Convert integer to binary, handling proper encoding
    int
    |> Integer.to_string(16)
    |> String.upcase()
    |> then(fn hex ->
      # Ensure even number of characters
      if rem(String.length(hex), 2) == 1, do: "0" <> hex, else: hex
    end)
    |> Base.decode16!()
  end
end
