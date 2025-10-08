defmodule AuthifyWeb.OAuthHTML do
  use AuthifyWeb, :html

  embed_templates "oauth_html/*"

  def scope_description("openid"), do: "Verify your identity"
  def scope_description("profile"), do: "Access your basic profile information (name)"
  def scope_description("email"), do: "Access your email address"
  def scope_description(scope), do: "Access #{scope} information"
end
