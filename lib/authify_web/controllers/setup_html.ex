defmodule AuthifyWeb.SetupHTML do
  @moduledoc """
  This module contains pages rendered by SetupController.
  """

  use AuthifyWeb, :html

  embed_templates "setup_html/*"
end
