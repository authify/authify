defmodule Authify.Repo do
  use Ecto.Repo,
    otp_app: :authify,
    adapter: Ecto.Adapters.MyXQL
end
