defmodule AuthifyWeb.UsersHTML do
  @moduledoc """
  This module contains pages rendered by UsersController.
  """
  use AuthifyWeb, :html

  embed_templates "users_html/*"
end
