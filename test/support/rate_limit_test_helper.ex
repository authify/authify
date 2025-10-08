defmodule Authify.RateLimitTestHelper do
  @moduledoc """
  Test helper for enabling rate limiting in specific tests.

  By default, rate limiting is disabled in the test environment to prevent
  tests from interfering with each other. Use this module to enable rate
  limiting for specific tests that need to verify rate limiting behavior.

  ## Usage

  ```elixir
  defmodule MyTest do
    use ExUnit.Case
    import Authify.RateLimitTestHelper

    setup do
      # Enable rate limiting for this test
      enable_rate_limiting()
    end

    test "rate limiting blocks too many requests" do
      # Your test code that expects rate limiting to work
    end
  end
  ```

  Or for a single test:

  ```elixir
  test "rate limiting works" do
    enable_rate_limiting()
    # Your test code
  end
  ```
  """

  @doc """
  Enables rate limiting for the current test.

  This sets the `:rate_limiting_enabled` application config to `true`
  for the duration of the test. It automatically resets to `false`
  when the test completes using ExUnit's `on_exit/1` callback.
  """
  def enable_rate_limiting do
    # Store the original value
    original_value = Application.get_env(:authify, :rate_limiting_enabled, false)

    # Enable rate limiting
    Application.put_env(:authify, :rate_limiting_enabled, true)

    # Reset to original value after test
    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:authify, :rate_limiting_enabled, original_value)
    end)

    :ok
  end

  @doc """
  Explicitly disables rate limiting for the current test.

  This is useful if you want to be explicit about disabling rate limiting,
  though it's disabled by default in tests.
  """
  def disable_rate_limiting do
    # Store the original value
    original_value = Application.get_env(:authify, :rate_limiting_enabled, false)

    # Disable rate limiting
    Application.put_env(:authify, :rate_limiting_enabled, false)

    # Reset to original value after test
    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:authify, :rate_limiting_enabled, original_value)
    end)

    :ok
  end

  @doc """
  Clears all Hammer rate limit buckets.

  This is useful when you need to reset rate limits between tests
  or during a test that makes multiple rate-limited requests.

  Uses Authify.RateLimit.set/3 function to reset all known bucket counters to 0.
  """
  def clear_rate_limits do
    # Reset all known bucket types to 0
    # We use 127.0.0.1 since tests all come from this IP
    scopes = ["auth", "oauth", "saml", "api", "generic", "custom"]
    identifiers = ["127.0.0.1"]

    for scope <- scopes, identifier <- identifiers do
      bucket_key = "#{scope}:#{identifier}"
      # Set the count to 0 for each bucket
      # Authify.RateLimit.set/3 takes (key, scale_ms, count)
      # Using 60_000ms to match our typical rate limit windows
      Authify.RateLimit.set(bucket_key, 60_000, 0)
    end

    :ok
  end
end
