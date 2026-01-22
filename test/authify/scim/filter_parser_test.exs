defmodule Authify.SCIM.FilterParserTest do
  use ExUnit.Case, async: true

  alias Authify.SCIM.FilterParser

  describe "parse/1 - basic comparison operators" do
    test "parses eq (equals) operator" do
      assert {:ok, {:eq, "userName", "jsmith"}} = FilterParser.parse(~s(userName eq "jsmith"))
    end

    test "parses ne (not equals) operator" do
      assert {:ok, {:ne, "userName", "jsmith"}} = FilterParser.parse(~s(userName ne "jsmith"))
    end

    test "parses co (contains) operator" do
      assert {:ok, {:co, "userName", "smith"}} = FilterParser.parse(~s(userName co "smith"))
    end

    test "parses sw (starts with) operator" do
      assert {:ok, {:sw, "userName", "j"}} = FilterParser.parse(~s(userName sw "j"))
    end

    test "parses ew (ends with) operator" do
      assert {:ok, {:ew, "userName", "smith"}} = FilterParser.parse(~s(userName ew "smith"))
    end

    test "parses pr (present) operator" do
      assert {:ok, {:pr, "userName"}} = FilterParser.parse("userName pr")
    end

    test "parses gt (greater than) operator" do
      assert {:ok, {:gt, "meta.lastModified", "2024-01-01T00:00:00Z"}} =
               FilterParser.parse(~s(meta.lastModified gt "2024-01-01T00:00:00Z"))
    end

    test "parses ge (greater than or equal) operator" do
      assert {:ok, {:ge, "meta.lastModified", "2024-01-01T00:00:00Z"}} =
               FilterParser.parse(~s(meta.lastModified ge "2024-01-01T00:00:00Z"))
    end

    test "parses lt (less than) operator" do
      assert {:ok, {:lt, "meta.lastModified", "2024-01-01T00:00:00Z"}} =
               FilterParser.parse(~s(meta.lastModified lt "2024-01-01T00:00:00Z"))
    end

    test "parses le (less than or equal) operator" do
      assert {:ok, {:le, "meta.lastModified", "2024-01-01T00:00:00Z"}} =
               FilterParser.parse(~s(meta.lastModified le "2024-01-01T00:00:00Z"))
    end
  end

  describe "parse/1 - boolean and null values" do
    test "parses boolean true value" do
      assert {:ok, {:eq, "active", "true"}} = FilterParser.parse("active eq true")
    end

    test "parses boolean false value" do
      assert {:ok, {:eq, "active", "false"}} = FilterParser.parse("active eq false")
    end

    test "parses null value" do
      assert {:ok, {:eq, "externalId", "null"}} = FilterParser.parse("externalId eq null")
    end
  end

  describe "parse/1 - logical operators" do
    test "parses and operator" do
      assert {:ok, {:and, {:eq, "active", "true"}, {:sw, "userName", "j"}}} =
               FilterParser.parse(~s(active eq true and userName sw "j"))
    end

    test "parses or operator" do
      assert {:ok, {:or, {:eq, "userName", "jsmith"}, {:eq, "userName", "bjensen"}}} =
               FilterParser.parse(~s(userName eq "jsmith" or userName eq "bjensen"))
    end

    test "parses not operator" do
      assert {:ok, {:not, {:eq, "active", "false"}}} =
               FilterParser.parse("not (active eq false)")
    end

    test "parses chained and operators" do
      assert {:ok,
              {:and, {:and, {:eq, "active", "true"}, {:sw, "userName", "j"}}, {:pr, "externalId"}}} =
               FilterParser.parse(~s(active eq true and userName sw "j" and externalId pr))
    end

    test "parses chained or operators" do
      assert {:ok,
              {:or, {:or, {:eq, "userName", "a"}, {:eq, "userName", "b"}}, {:eq, "userName", "c"}}} =
               FilterParser.parse(~s(userName eq "a" or userName eq "b" or userName eq "c"))
    end

    test "parses mixed and/or operators (and has higher precedence)" do
      # userName eq "a" and active eq true or userName eq "b"
      # Should parse as: (userName eq "a" and active eq true) or userName eq "b"
      assert {:ok,
              {:or, {:and, {:eq, "userName", "a"}, {:eq, "active", "true"}},
               {:eq, "userName", "b"}}} =
               FilterParser.parse(~s(userName eq "a" and active eq true or userName eq "b"))
    end
  end

  describe "parse/1 - parentheses and grouping" do
    test "parses parentheses for precedence override" do
      # (userName eq "a" or userName eq "b") and active eq true
      assert {:ok,
              {:and, {:or, {:eq, "userName", "a"}, {:eq, "userName", "b"}},
               {:eq, "active", "true"}}} =
               FilterParser.parse(~s{(userName eq "a" or userName eq "b") and active eq true})
    end

    test "parses nested parentheses" do
      assert {:ok,
              {:and, {:or, {:eq, "userName", "a"}, {:eq, "userName", "b"}},
               {:not, {:eq, "active", "false"}}}} =
               FilterParser.parse(
                 ~s{(userName eq "a" or userName eq "b") and not (active eq false)}
               )
    end
  end

  describe "parse/1 - complex attribute paths" do
    test "parses dotted attribute paths" do
      assert {:ok, {:eq, "name.givenName", "John"}} =
               FilterParser.parse(~s(name.givenName eq "John"))
    end

    test "parses multi-level dotted paths" do
      assert {:ok, {:eq, "user.name.givenName", "John"}} =
               FilterParser.parse(~s(user.name.givenName eq "John"))
    end

    test "parses filtered attribute expressions" do
      # emails[type eq "work"]
      # Complex filtered attribute expressions return a tuple with path and filter list
      result = FilterParser.parse(~s(emails[type eq "work"]))

      # The parser returns a tuple with the attribute path and filter in a list
      assert {:ok, {"emails", [{:eq, "type", "work"}]}} = result
    end
  end

  describe "parse/1 - case insensitivity" do
    test "parses operators in different cases" do
      assert {:ok, {:eq, "userName", "test"}} = FilterParser.parse(~s(userName EQ "test"))
      assert {:ok, {:eq, "userName", "test"}} = FilterParser.parse(~s(userName Eq "test"))
      assert {:ok, {:eq, "userName", "test"}} = FilterParser.parse(~s(userName eQ "test"))
    end

    test "parses logical operators in different cases" do
      assert {:ok, {:and, {:eq, "active", "true"}, {:pr, "userName"}}} =
               FilterParser.parse("active eq true AND userName pr")

      assert {:ok, {:and, {:eq, "active", "true"}, {:pr, "userName"}}} =
               FilterParser.parse("active eq true And userName pr")

      assert {:ok, {:or, {:eq, "userName", "a"}, {:eq, "userName", "b"}}} =
               FilterParser.parse(~s(userName eq "a" OR userName eq "b"))
    end

    test "parses not operator in different cases" do
      assert {:ok, {:not, {:eq, "active", "false"}}} =
               FilterParser.parse("NOT (active eq false)")

      assert {:ok, {:not, {:eq, "active", "false"}}} =
               FilterParser.parse("Not (active eq false)")
    end

    test "parses pr operator in different cases" do
      assert {:ok, {:pr, "userName"}} = FilterParser.parse("userName PR")
      assert {:ok, {:pr, "userName"}} = FilterParser.parse("userName Pr")
      assert {:ok, {:pr, "userName"}} = FilterParser.parse("userName pR")
    end
  end

  describe "parse/1 - whitespace handling" do
    test "parses with extra whitespace between tokens" do
      # Extra whitespace between operator and value
      assert {:ok, {:eq, "userName", "jsmith"}} =
               FilterParser.parse(~s(userName   eq   "jsmith"))
    end

    test "parses with minimal whitespace" do
      assert {:ok, {:eq, "userName", "jsmith"}} = FilterParser.parse(~s(userName eq "jsmith"))
    end

    test "parses with newlines and tabs" do
      assert {:ok, {:and, {:eq, "userName", "jsmith"}, {:eq, "active", "true"}}} =
               FilterParser.parse("userName eq \"jsmith\"\n\tand\nactive eq true")
    end
  end

  describe "parse/1 - special characters in values" do
    test "parses values with spaces" do
      assert {:ok, {:eq, "name.givenName", "John Smith"}} =
               FilterParser.parse(~s(name.givenName eq "John Smith"))
    end

    test "parses values with special characters" do
      assert {:ok, {:eq, "userName", "user@example.com"}} =
               FilterParser.parse(~s(userName eq "user@example.com"))
    end

    test "parses attribute paths with colons and slashes" do
      # SCIM allows : / - _ in attribute names
      assert {:ok,
              {:eq, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
               "Engineering"}} =
               FilterParser.parse(
                 ~s(urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Engineering")
               )
    end
  end

  describe "parse/1 - error cases" do
    test "returns error for empty string" do
      assert {:error, _} = FilterParser.parse("")
    end

    test "returns error for invalid syntax" do
      assert {:error, _} = FilterParser.parse("userName invalid syntax")
    end

    test "returns error for unclosed quotes" do
      assert {:error, _} = FilterParser.parse(~s(userName eq "unclosed))
    end

    test "returns error for unmatched parentheses" do
      assert {:error, _} = FilterParser.parse(~s{(userName eq "test"})
      assert {:error, _} = FilterParser.parse(~s{userName eq "test")})
    end

    test "returns error for invalid operator" do
      assert {:error, _} = FilterParser.parse(~s(userName invalid "test"))
    end

    test "returns error for non-string input" do
      assert {:error, "Filter must be a string"} = FilterParser.parse(123)
      assert {:error, "Filter must be a string"} = FilterParser.parse(%{})
    end
  end

  describe "parse/1 - nil handling" do
    test "returns ok with nil AST for nil input" do
      assert {:ok, nil} = FilterParser.parse(nil)
    end
  end

  describe "parse/1 - real-world SCIM filter examples" do
    test "parses Workday-style user filter" do
      # Find active user by email
      assert {:ok,
              {:and, {:eq, "emails.value", "john.smith@example.com"}, {:eq, "active", "true"}}} =
               FilterParser.parse(~s(emails.value eq "john.smith@example.com" and active eq true))
    end

    test "parses BambooHR-style user filter" do
      # Find users whose username starts with a prefix
      assert {:ok, {:and, {:sw, "userName", "emp_"}, {:pr, "externalId"}}} =
               FilterParser.parse(~s(userName sw "emp_" and externalId pr))
    end

    test "parses ADP-style filter with multiple conditions" do
      # Find inactive users modified after a certain date
      assert {:ok,
              {:and, {:eq, "active", "false"}, {:gt, "meta.lastModified", "2024-01-01T00:00:00Z"}}} =
               FilterParser.parse(
                 ~s(active eq false and meta.lastModified gt "2024-01-01T00:00:00Z")
               )
    end

    test "parses complex group membership filter" do
      # Find users in specific groups
      assert {:ok,
              {:or, {:eq, "groups.displayName", "Engineering"},
               {:eq, "groups.displayName", "Sales"}}} =
               FilterParser.parse(
                 ~s(groups.displayName eq "Engineering" or groups.displayName eq "Sales")
               )
    end

    test "parses external ID lookup" do
      assert {:ok, {:eq, "externalId", "hr-12345"}} =
               FilterParser.parse(~s(externalId eq "hr-12345"))
    end
  end
end
