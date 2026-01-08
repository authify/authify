defmodule AuthifyWeb.MfaHTML do
  @moduledoc """
  HTML templates for MFA (Multi-Factor Authentication) management.
  """
  use AuthifyWeb, :html

  embed_templates "mfa_html/*"
end
