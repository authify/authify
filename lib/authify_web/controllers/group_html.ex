defmodule AuthifyWeb.GroupHTML do
  use AuthifyWeb, :html

  embed_templates "group_html/*"

  @doc """
  Renders a group form.

  The form is defined in the template at
  group_html/group_form.html.heex
  """
  attr :changeset, Ecto.Changeset, required: true
  attr :action, :string, required: true
  attr :return_to, :string, default: nil

  def group_form(assigns)
end
