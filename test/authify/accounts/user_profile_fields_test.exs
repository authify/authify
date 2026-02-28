defmodule Authify.Accounts.UserProfileFieldsTest do
  use Authify.DataCase

  alias Authify.Accounts
  alias Authify.Accounts.User

  import Authify.AccountsFixtures

  describe "extended profile fields in changeset" do
    test "changeset accepts locale, zoneinfo, phone_number, team, title" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      attrs = %{
        "locale" => "en-US",
        "zoneinfo" => "America/New_York",
        "phone_number" => "+15555551234",
        "team" => "Platform",
        "title" => "Senior Engineer"
      }

      changeset = User.changeset(user, attrs)
      assert changeset.valid?
      assert get_change(changeset, :locale) == "en-US"
      assert get_change(changeset, :zoneinfo) == "America/New_York"
      assert get_change(changeset, :phone_number) == "+15555551234"
      assert get_change(changeset, :team) == "Platform"
      assert get_change(changeset, :title) == "Senior Engineer"
    end

    test "changeset accepts valid E.164 phone numbers" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      for number <- ["+12125551234", "+447911123456", "+33612345678", "+819012345678"] do
        changeset = User.changeset(user, %{"phone_number" => number})
        assert changeset.valid?, "Expected #{number} to be valid"
      end
    end

    test "changeset normalises spaces, dashes, dots, and parens before validation" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      # These should all normalise to valid E.164 and be accepted
      inputs_and_expected = [
        {"+1 (212) 555-1234", "+12125551234"},
        {"+44 7911 123 456", "+447911123456"},
        {"+33 6.12.34.56.78", "+33612345678"}
      ]

      for {input, expected} <- inputs_and_expected do
        changeset = User.changeset(user, %{"phone_number" => input})
        assert changeset.valid?, "Expected #{input} to be valid after normalisation"
        assert get_change(changeset, :phone_number) == expected
      end
    end

    test "changeset rejects phone numbers that are still invalid after normalisation" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      # No leading +, too short, or leading zero after +
      for bad <- ["5551234", "12125551234", "+0123456"] do
        changeset = User.changeset(user, %{"phone_number" => bad})
        refute changeset.valid?, "Expected #{bad} to be invalid"
        assert "must be in E.164 format (e.g. +12125551234)" in errors_on(changeset).phone_number
      end
    end

    test "changeset ignores empty phone_number (no validation error)" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"phone_number" => ""})
      assert changeset.valid?
    end

    test "changeset accepts valid avatar_url with http" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"avatar_url" => "http://example.com/avatar.png"})
      assert changeset.valid?
    end

    test "changeset accepts valid avatar_url with https" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"avatar_url" => "https://example.com/avatar.png"})
      assert changeset.valid?
    end

    test "changeset rejects avatar_url without http/https" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"avatar_url" => "ftp://example.com/avatar.png"})
      refute changeset.valid?

      assert "must be a valid URL starting with http:// or https://" in errors_on(changeset).avatar_url
    end

    test "changeset accepts valid website with https" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"website" => "https://myblog.example.com"})
      assert changeset.valid?
    end

    test "changeset rejects website without http/https" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"website" => "not-a-url"})
      refute changeset.valid?

      assert "must be a valid URL starting with http:// or https://" in errors_on(changeset).website
    end

    test "changeset ignores empty avatar_url (no validation error)" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"avatar_url" => ""})
      assert changeset.valid?
    end

    test "changeset ignores empty website (no validation error)" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      changeset = User.changeset(user, %{"website" => ""})
      assert changeset.valid?
    end

    test "changeset resets phone_number_verified to false when phone_number changes" do
      organization = organization_fixture()

      {:ok, user} =
        Accounts.update_user(
          user_for_organization_fixture(organization),
          %{"phone_number" => "+10000000000", "phone_number_verified" => true}
        )

      assert user.phone_number_verified == true

      changeset = User.changeset(user, %{"phone_number" => "+19999999999"})
      assert changeset.valid?
      assert get_change(changeset, :phone_number_verified) == false
    end

    test "changeset does NOT reset phone_number_verified when caller also sets it" do
      organization = organization_fixture()

      # Start with phone_number_verified: false (the default) so when we cast true
      # it becomes an actual change in changeset.changes
      user = user_for_organization_fixture(organization)
      assert user.phone_number_verified == false

      changeset =
        User.changeset(user, %{"phone_number" => "+19999999999", "phone_number_verified" => true})

      assert changeset.valid?
      # phone_number_verified should remain true as explicitly requested
      assert get_change(changeset, :phone_number_verified) == true
    end
  end

  describe "avatar_url/1 helper" do
    test "returns custom avatar_url when set" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      {:ok, user} =
        Accounts.update_user(user, %{"avatar_url" => "https://cdn.example.com/me.jpg"})

      assert User.avatar_url(user) == "https://cdn.example.com/me.jpg"
    end

    test "returns gravatar URL when avatar_url is nil" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      user = Authify.Repo.preload(user, :emails)

      assert is_nil(user.avatar_url)

      url = User.avatar_url(user)
      assert is_binary(url)
      assert String.starts_with?(url, "https://www.gravatar.com/avatar/")
      assert String.contains?(url, "s=200&d=identicon")
    end

    test "returns gravatar URL when emails are not preloaded (falls back to DB query)" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)
      # Strip the preloaded emails association to simulate unloaded
      user_no_emails = %{
        user
        | emails: %Ecto.Association.NotLoaded{
            __field__: :emails,
            __owner__: User,
            __cardinality__: :many
          }
      }

      # Even without preloaded emails, avatar_url/1 queries the DB and returns a Gravatar
      url = User.avatar_url(user_no_emails)
      assert is_binary(url)
      assert String.starts_with?(url, "https://www.gravatar.com/avatar/")
    end
  end

  describe "update_user_profile/2 field filtering" do
    test "allows user-editable fields through" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      {:ok, updated} =
        Accounts.update_user_profile(user, %{
          "locale" => "fr-FR",
          "zoneinfo" => "Europe/Paris",
          "phone_number" => "+33123456789",
          "website" => "https://monblog.fr",
          "avatar_url" => "https://cdn.example.com/photo.jpg"
        })

      assert updated.locale == "fr-FR"
      assert updated.zoneinfo == "Europe/Paris"
      assert updated.phone_number == "+33123456789"
      assert updated.website == "https://monblog.fr"
      assert updated.avatar_url == "https://cdn.example.com/photo.jpg"
    end

    test "blocks team and title from self-service update" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      {:ok, updated} =
        Accounts.update_user_profile(user, %{
          "first_name" => "Alice",
          "team" => "HACKED",
          "title" => "CEO"
        })

      assert updated.first_name == "Alice"
      assert is_nil(updated.team)
      assert is_nil(updated.title)
    end

    test "blocks phone_number_verified from self-service update" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      {:ok, updated} =
        Accounts.update_user_profile(user, %{
          "phone_number_verified" => true
        })

      assert updated.phone_number_verified == false
    end
  end

  describe "admin update_user/2 allows all fields" do
    test "admin can set team and title" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      {:ok, updated} =
        Accounts.update_user(user, %{"team" => "Platform", "title" => "Principal Engineer"})

      assert updated.team == "Platform"
      assert updated.title == "Principal Engineer"
    end

    test "admin can set phone_number_verified directly" do
      organization = organization_fixture()
      user = user_for_organization_fixture(organization)

      {:ok, with_phone} =
        Accounts.update_user(user, %{
          "phone_number" => "+15555550000",
          "phone_number_verified" => true
        })

      assert with_phone.phone_number == "+15555550000"
      assert with_phone.phone_number_verified == true
    end
  end
end
