defmodule AuthifyTest.SAMLServiceProviderTest do
  use AuthifyWeb.ConnCase, async: true

  import Authify.AccountsFixtures

  alias AuthifyTest.SAMLServiceProvider

  describe "new/2" do
    setup do: %{org: organization_fixture()}

    test "generates an RSA private key (PEM)", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert is_binary(sp.private_key)
      assert String.contains?(sp.private_key, "PRIVATE KEY")
      assert [_] = :public_key.pem_decode(sp.private_key)
    end

    test "generates a self-signed X.509 certificate (PEM)", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert is_binary(sp.certificate)
      assert String.contains?(sp.certificate, "BEGIN CERTIFICATE")
      [pem_entry] = :public_key.pem_decode(sp.certificate)
      cert = :public_key.pem_entry_decode(pem_entry)
      assert match?({:Certificate, _, _, _}, cert)
    end

    test "registers a service provider record in the database", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert sp.sp_record.id
      assert sp.sp_record.organization_id == org.id
      assert sp.sp_record.is_active
    end

    test "each call produces a unique entity_id", %{org: org} do
      sp1 = SAMLServiceProvider.new(org)
      sp2 = SAMLServiceProvider.new(org)
      refute sp1.entity_id == sp2.entity_id
    end

    test "accepts an explicit entity_id override via attrs", %{org: org} do
      sp = SAMLServiceProvider.new(org, %{entity_id: "https://custom-sp.example.com"})
      assert sp.entity_id == "https://custom-sp.example.com"
      assert sp.sp_record.entity_id == "https://custom-sp.example.com"
    end

    test "stores the SP certificate PEM in the DB record", %{org: org} do
      sp = SAMLServiceProvider.new(org)
      assert String.contains?(sp.sp_record.certificate, "BEGIN CERTIFICATE")
    end
  end
end
