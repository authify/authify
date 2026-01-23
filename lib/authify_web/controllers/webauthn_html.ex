defmodule AuthifyWeb.WebAuthnHTML do
  @moduledoc """
  HTML templates for WebAuthn credential management.
  """
  use AuthifyWeb, :html

  embed_templates "webauthn_html/*"
end
