defmodule AuthifyWeb.API.CertificatesControllerTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  setup %{conn: conn} do
    organization = organization_fixture()
    admin_user = user_fixture(organization: organization, role: "admin")

    # Generate test certificates directly using the existing functionality
    {:ok, certificate1} =
      Authify.Accounts.generate_saml_signing_certificate(organization, %{
        "name" => "SAML Signing Cert",
        "usage" => "saml_signing"
      })

    {:ok, certificate2} =
      Authify.Accounts.generate_saml_signing_certificate(organization, %{
        "name" => "OAuth Signing Cert",
        "usage" => "oauth_signing"
      })

    # Deactivate the second certificate for testing
    {:ok, certificate2} =
      Authify.Accounts.update_certificate(certificate2, %{"is_active" => false})

    # Set up API headers and authentication as admin
    conn =
      conn
      |> put_req_header("accept", "application/vnd.authify.v1+json")
      |> put_req_header("content-type", "application/vnd.authify.v1+json")
      |> log_in_user(admin_user)
      |> assign(:current_user, admin_user)
      |> assign(:current_organization, organization)
      |> assign(:api_authenticated, true)
      |> assign(:current_scopes, ["certificates:read", "certificates:write"])

    %{
      conn: conn,
      admin_user: admin_user,
      organization: organization,
      certificate1: certificate1,
      certificate2: certificate2
    }
  end

  describe "GET /api/certificates" do
    test "returns paginated list of certificates with HATEOAS", %{
      conn: conn,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/certificates")

      assert %{
               "data" => certificates,
               "links" => %{
                 "self" => _self_link,
                 "first" => _first_link
               },
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 25
               }
             } = json_response(conn, 200)

      assert length(certificates) == 2

      # Check certificate structure
      cert_data = List.first(certificates)

      assert %{
               "id" => _,
               "type" => "certificate",
               "attributes" => attributes,
               "links" => %{"self" => _self_link}
             } = cert_data

      # Verify private key is excluded
      refute Map.has_key?(attributes, "private_key")

      # Verify expected attributes are present
      assert Map.has_key?(attributes, "name")
      assert Map.has_key?(attributes, "usage")
      assert Map.has_key?(attributes, "is_active")
      assert Map.has_key?(attributes, "expires_at")
    end

    test "supports pagination parameters", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/certificates?page=1&per_page=1")

      assert %{
               "data" => certificates,
               "meta" => %{
                 "total" => 2,
                 "page" => 1,
                 "per_page" => 1
               }
             } = json_response(conn, 200)

      assert length(certificates) == 1
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection as regular user
      conn =
        conn
        # Regular user without certificate scopes
        |> assign(:current_scopes, ["profile:read"])

      conn = get(conn, "/#{organization.slug}/api/certificates")

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end
  end

  describe "GET /api/certificates/:id" do
    test "returns certificate details", %{
      conn: conn,
      certificate1: certificate,
      organization: organization
    } do
      conn = get(conn, "/#{organization.slug}/api/certificates/#{certificate.id}")

      assert %{
               "data" => %{
                 "id" => id,
                 "type" => "certificate",
                 "attributes" => attributes,
                 "links" => %{"self" => _self_link}
               }
             } = json_response(conn, 200)

      assert id == to_string(certificate.id)
      assert attributes["name"] == certificate.name
      assert attributes["usage"] == certificate.usage
      refute Map.has_key?(attributes, "private_key")
    end

    test "returns 404 for non-existent certificate", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/certificates/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found",
                 "message" => "Certificate not found in organization"
               }
             } = json_response(conn, 404)
    end
  end

  describe "POST /api/certificates" do
    test "creates certificate with valid manual data", %{conn: conn, organization: organization} do
      # Generate a fresh certificate for manual upload test
      {:ok, temp_cert} =
        Authify.Accounts.generate_saml_signing_certificate(organization, %{
          "name" => "Temp Cert for Manual Test",
          "usage" => "saml_signing"
        })

      cert_attrs = %{
        "certificate" => %{
          "name" => "Test Manual Cert",
          "usage" => "saml_signing",
          "certificate" => temp_cert.certificate,
          "private_key" => temp_cert.private_key,
          "is_active" => false
        }
      }

      conn = post(conn, "/#{organization.slug}/api/certificates", cert_attrs)

      assert %{
               "data" => %{
                 "type" => "certificate",
                 "attributes" => attributes
               }
             } = json_response(conn, 201)

      assert attributes["name"] == "Test Manual Cert"
      assert attributes["usage"] == "saml_signing"
      assert attributes["is_active"] == false
      refute Map.has_key?(attributes, "private_key")

      # Clean up the temp certificate
      Authify.Accounts.delete_certificate(temp_cert)
    end

    test "generates new certificate when requested", %{conn: conn, organization: organization} do
      cert_attrs = %{
        "certificate" => %{
          "name" => "Generated SAML Cert",
          "usage" => "saml_signing",
          "generate_new" => "true"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/certificates", cert_attrs)

      assert %{
               "data" => %{
                 "type" => "certificate",
                 "attributes" => attributes
               }
             } = json_response(conn, 201)

      assert attributes["name"] == "Generated SAML Cert"
      assert attributes["usage"] == "saml_signing"
      refute Map.has_key?(attributes, "private_key")
    end

    test "returns validation errors for invalid data", %{conn: conn, organization: organization} do
      invalid_attrs = %{
        "certificate" => %{
          "name" => "",
          "usage" => "invalid_usage"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/certificates", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["name"]
      assert details["usage"]
    end

    test "requires appropriate Management API scopes", %{conn: conn, organization: organization} do
      # Set up connection as regular user
      conn =
        conn
        # Regular user without certificate scopes
        |> assign(:current_scopes, ["profile:read"])

      cert_attrs = %{
        "certificate" => %{
          "name" => "Test Cert",
          "usage" => "saml_signing",
          "generate_new" => "true"
        }
      }

      conn = post(conn, "/#{organization.slug}/api/certificates", cert_attrs)

      assert %{
               "error" => %{
                 "type" => "insufficient_scope",
                 "message" => "Insufficient scope to access this resource"
               }
             } = json_response(conn, 403)
    end

    test "returns error for missing certificate parameters", %{
      conn: conn,
      organization: organization
    } do
      conn = post(conn, "/#{organization.slug}/api/certificates", %{})

      assert %{
               "error" => %{
                 "type" => "invalid_request",
                 "message" => "Request must include certificate parameters"
               }
             } = json_response(conn, 400)
    end
  end

  describe "PUT /api/certificates/:id" do
    test "updates certificate with valid data", %{
      conn: conn,
      certificate1: certificate,
      organization: organization
    } do
      update_attrs = %{
        "certificate" => %{
          "name" => "Updated Certificate Name"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/certificates/#{certificate.id}", update_attrs)

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["name"] == "Updated Certificate Name"
    end

    test "returns validation errors for invalid data", %{
      conn: conn,
      certificate1: certificate,
      organization: organization
    } do
      invalid_attrs = %{
        "certificate" => %{
          "usage" => "invalid_usage"
        }
      }

      conn = put(conn, "/#{organization.slug}/api/certificates/#{certificate.id}", invalid_attrs)

      assert %{
               "error" => %{
                 "type" => "validation_failed",
                 "details" => details
               }
             } = json_response(conn, 422)

      assert details["usage"]
    end

    test "returns 404 for non-existent certificate", %{conn: conn, organization: organization} do
      conn =
        put(conn, "/#{organization.slug}/api/certificates/99999", %{
          "certificate" => %{"name" => "Updated"}
        })

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end
  end

  describe "DELETE /api/certificates/:id" do
    test "deletes certificate", %{
      conn: conn,
      certificate2: certificate,
      organization: organization
    } do
      conn = delete(conn, "/#{organization.slug}/api/certificates/#{certificate.id}")

      assert response(conn, 204)
    end

    test "returns 404 for non-existent certificate", %{conn: conn, organization: organization} do
      conn = delete(conn, "/#{organization.slug}/api/certificates/99999")

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end
  end

  describe "PATCH /api/certificates/:id/activate" do
    test "activates certificate", %{
      conn: conn,
      certificate2: certificate,
      organization: organization
    } do
      conn = patch(conn, "/#{organization.slug}/api/certificates/#{certificate.id}/activate")

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["is_active"] == true
    end

    test "returns 404 for non-existent certificate", %{conn: conn, organization: organization} do
      conn = patch(conn, "/#{organization.slug}/api/certificates/99999/activate")

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end
  end

  describe "PATCH /api/certificates/:id/deactivate" do
    test "deactivates certificate", %{
      conn: conn,
      certificate1: certificate,
      organization: organization
    } do
      conn = patch(conn, "/#{organization.slug}/api/certificates/#{certificate.id}/deactivate")

      assert %{
               "data" => %{
                 "attributes" => attributes
               }
             } = json_response(conn, 200)

      assert attributes["is_active"] == false
    end

    test "returns 404 for non-existent certificate", %{conn: conn, organization: organization} do
      conn = patch(conn, "/#{organization.slug}/api/certificates/99999/deactivate")

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end
  end

  describe "GET /api/certificates/:id/download/:type" do
    test "downloads certificate file", %{
      conn: conn,
      certificate1: certificate,
      organization: organization
    } do
      conn =
        get(conn, "/#{organization.slug}/api/certificates/#{certificate.id}/download/certificate")

      assert response(conn, 200)
      [content_type] = get_resp_header(conn, "content-type")
      assert String.starts_with?(content_type, "application/x-pem-file")

      assert get_resp_header(conn, "content-disposition") == [
               "attachment; filename=\"SAML_Signing_Cert_certificate.pem\""
             ]
    end

    test "downloads private key file", %{
      conn: conn,
      certificate1: certificate,
      organization: organization
    } do
      conn =
        get(conn, "/#{organization.slug}/api/certificates/#{certificate.id}/download/private_key")

      assert response(conn, 200)
      [content_type] = get_resp_header(conn, "content-type")
      assert String.starts_with?(content_type, "application/x-pem-file")

      assert get_resp_header(conn, "content-disposition") == [
               "attachment; filename=\"SAML_Signing_Cert_private_key.pem\""
             ]
    end

    test "returns error for invalid download type", %{
      conn: conn,
      certificate1: certificate,
      organization: organization
    } do
      conn =
        get(
          conn,
          "/#{organization.slug}/api/certificates/#{certificate.id}/download/invalid_type"
        )

      assert %{
               "error" => %{
                 "type" => "invalid_request",
                 "message" =>
                   "Invalid download type: invalid_type. Must be 'certificate' or 'private_key'"
               }
             } = json_response(conn, 400)
    end

    test "returns 404 for non-existent certificate", %{conn: conn, organization: organization} do
      conn = get(conn, "/#{organization.slug}/api/certificates/99999/download/certificate")

      assert %{
               "error" => %{
                 "type" => "resource_not_found"
               }
             } = json_response(conn, 404)
    end
  end
end
