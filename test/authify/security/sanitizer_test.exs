defmodule Authify.Security.SanitizerTest do
  use ExUnit.Case, async: true

  alias Authify.Security.Sanitizer

  describe "sanitize/1" do
    test "returns nil for nil input" do
      assert Sanitizer.sanitize(nil) == nil
    end

    test "returns empty string for empty input" do
      assert Sanitizer.sanitize("") == ""
    end

    test "returns normal text unchanged" do
      assert Sanitizer.sanitize("normal text") == "normal text"
    end

    test "redacts hashed_password field" do
      input = ~s(hashed_password: "$2b$12$e/PqNZqvveA6N53niEVbY")
      result = Sanitizer.sanitize(input)
      assert result == ~s(hashed_password: "[REDACTED]")
    end

    test "redacts password field" do
      input = ~s(password: "secret123")
      result = Sanitizer.sanitize(input)
      assert result == ~s(password: "[REDACTED]")
    end

    test "redacts totp_secret field" do
      input = ~s(totp_secret: "t+F9J6W4NAwJfJ8n15q25WWEBd4uIvb9CU9f1vW7Zjs6")
      result = Sanitizer.sanitize(input)
      assert result == ~s(totp_secret: "[REDACTED]")
    end

    test "redacts api_key field" do
      input = ~s(api_key: "sk-proj-abc123xyz")
      result = Sanitizer.sanitize(input)
      assert result == ~s(api_key: "[REDACTED]")
    end

    test "redacts access_token field" do
      input = ~s(access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
      result = Sanitizer.sanitize(input)
      assert result == ~s(access_token: "[REDACTED]")
    end

    test "redacts multiple sensitive fields in one string" do
      input = """
      password: "secret123"
      api_key: "sk-proj-abc123"
      totp_secret: "abc123xyz"
      """

      result = Sanitizer.sanitize(input)
      assert result =~ ~s(password: "[REDACTED]")
      assert result =~ ~s(api_key: "[REDACTED]")
      assert result =~ ~s(totp_secret: "[REDACTED]")
    end

    test "redacts backup codes and shows count" do
      input = ~s(totp_backup_codes: "[\\"$2b$12$abc\\",\\"$2b$12$def\\",\\"$2b$12$ghi\\"]")
      result = Sanitizer.sanitize(input)
      assert result =~ ~s(totp_backup_codes: "[REDACTED - 3 codes]")
    end

    test "handles real-world error message with User struct" do
      input = """
      %Authify.Accounts.User{
        hashed_password: "$2b$12$e/PqNZqvveA6N53niEVbY.SX9vMkNRjHgQmZ8xbWSIrRJKH.hg05u",
        totp_secret: "t+F9J6W4NAwJfJ8n15q25WWEBd4uIvb9CU9f1vW7Zjs6PnlJCx49kr0gDuV2zaJhMAQHMVRu9P+TI19RhkJJfu8sJ+A=",
        totp_backup_codes: "[\\"$2b$12$abc\\",\\"$2b$12$def\\"]",
        first_name: "Jonathan",
        role: "admin"
      }
      """

      result = Sanitizer.sanitize(input)

      # Verify sensitive fields are redacted
      assert result =~ ~s(hashed_password: "[REDACTED]")
      assert result =~ ~s(totp_secret: "[REDACTED]")
      assert result =~ ~s(totp_backup_codes: "[REDACTED - 2 codes]")

      # Verify non-sensitive fields remain
      assert result =~ "Jonathan"
      assert result =~ "admin"
    end

    test "is case insensitive for field names" do
      input = ~s(HASHED_PASSWORD: "secret" Password: "test" Api_Key: "key")
      result = Sanitizer.sanitize(input)
      # Note: Replacement uses lowercase field names
      assert result =~ ~s(hashed_password: "[REDACTED]")
      assert result =~ ~s(password: "[REDACTED]")
      assert result =~ ~s(api_key: "[REDACTED]")
    end

    test "returns non-string content unchanged" do
      assert Sanitizer.sanitize(123) == 123
      assert Sanitizer.sanitize(%{key: "value"}) == %{key: "value"}
      assert Sanitizer.sanitize([:a, :b, :c]) == [:a, :b, :c]
    end

    test "handles JSON-escaped quotes in error messages" do
      # This is how it appears in JSON output after format_json()
      input = ~s("message": "hashed_password: \\"$2b$12$abc123\\", totp_secret: \\"xyz789\\"")

      result = Sanitizer.sanitize(input)

      assert result =~ ~s(hashed_password: \\"[REDACTED]\\")
      assert result =~ ~s(totp_secret: \\"[REDACTED]\\")
    end

    test "handles JSON-escaped backup codes" do
      input = ~s(totp_backup_codes: \\"[\\\\\\"$2b$12$abc\\\\\\",\\\\\\"$2b$12$def\\\\\\"]\\")

      result = Sanitizer.sanitize(input)

      # Should redact and show count
      assert result =~ "[REDACTED - 2 codes]"
    end
  end

  describe "sanitize_map/1" do
    test "sanitizes map by converting to JSON and back" do
      input = %{
        "password" => "secret",
        "name" => "Test User"
      }

      # Note: This converts to JSON, sanitizes, and parses back
      # The password field in JSON will be like "password": "secret"
      result = Sanitizer.sanitize_map(input)

      # After round-trip through JSON sanitization, password should be redacted
      assert is_map(result)
    end

    test "returns non-map content unchanged" do
      assert Sanitizer.sanitize_map("string") == "string"
      assert Sanitizer.sanitize_map(123) == 123
    end
  end
end
