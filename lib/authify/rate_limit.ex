defmodule Authify.RateLimit do
  @moduledoc """
  Rate limiting module using Hammer with ETS backend.

  This module is automatically started by the application supervisor
  and provides rate limiting functionality throughout the application.
  """

  use Hammer, backend: :ets
end
