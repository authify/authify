defmodule Authify.Accounts.OrganizationDeletionTest do
  # async: false — deleting an organization issues a cascading DELETE across
  # ~14 tables with ON DELETE CASCADE. Under concurrent MySQL sandbox
  # transactions this contends on locks and can exceed DBConnection's 15s
  # holder deadline, surfacing as "socket closed". Ecto's sandbox docs warn
  # that MySQL does not support concurrent transactional tests for exactly
  # this reason. Kept separate from the async AccountsTest so only this one
  # test runs serially.
  use Authify.DataCase, async: false

  alias Authify.Accounts
  alias Authify.Accounts.Organization

  describe "delete_organization/1" do
    test "deletes the organization" do
      n = System.unique_integer([:positive])

      {:ok, org} =
        Accounts.create_organization(%{name: "Test Organization #{n}", slug: "test-org-#{n}"})

      assert {:ok, %Organization{}} = Accounts.delete_organization(org)
      assert_raise Ecto.NoResultsError, fn -> Accounts.get_organization!(org.id) end
    end
  end
end
