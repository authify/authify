defmodule AuthifyWeb.AuditLogsHTMLTest do
  use ExUnit.Case, async: true

  alias AuthifyWeb.AuditLogsHTML

  describe "event_type_badge_class/1" do
    test "maps each event category to its badge class" do
      assert AuditLogsHTML.event_type_badge_class("oauth_client_updated") == "badge bg-purple"
      assert AuditLogsHTML.event_type_badge_class("scim_client_updated") == "badge bg-cyan"
      assert AuditLogsHTML.event_type_badge_class("saml_sp_created") == "badge bg-indigo"
      assert AuditLogsHTML.event_type_badge_class("user_updated") == "badge bg-warning"
      assert AuditLogsHTML.event_type_badge_class("user_login") == "badge bg-primary"
      assert AuditLogsHTML.event_type_badge_class("user_logout") == "badge bg-info"
      assert AuditLogsHTML.event_type_badge_class("role_updated") == "badge bg-danger"
      assert AuditLogsHTML.event_type_badge_class("settings_updated") == "badge bg-secondary"
    end

    test "custom badge utilities are defined in the application stylesheet" do
      css = File.read!(Path.join([File.cwd!(), "assets", "css", "app.css"]))

      for class <- ~w(bg-purple bg-cyan bg-indigo) do
        assert css =~ ".#{class}",
               "expected the #{class} utility to be defined in assets/css/app.css"
      end
    end
  end

  describe "outcome_badge_class/1" do
    test "maps each outcome to its badge class" do
      assert AuditLogsHTML.outcome_badge_class("success") == "badge bg-success"
      assert AuditLogsHTML.outcome_badge_class("failure") == "badge bg-danger"
      assert AuditLogsHTML.outcome_badge_class("denied") == "badge bg-warning"
      assert AuditLogsHTML.outcome_badge_class("unknown") == "badge bg-secondary"
    end
  end
end
