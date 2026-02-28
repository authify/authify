defmodule Authify.LocaleHelpers do
  @moduledoc """
  Provides curated lists of BCP 47 locales and IANA timezones for use in UI
  dropdowns. Values are stored as standard identifiers.
  """

  @doc """
  Returns a list of `{label, value}` tuples for common BCP 47 locales.
  """
  def locale_options do
    [
      {"Arabic", "ar"},
      {"Chinese (Simplified)", "zh-CN"},
      {"Chinese (Traditional)", "zh-TW"},
      {"Czech", "cs"},
      {"Danish", "da"},
      {"Dutch", "nl"},
      {"English (United Kingdom)", "en-GB"},
      {"English (United States)", "en-US"},
      {"Finnish", "fi"},
      {"French (Canada)", "fr-CA"},
      {"French (France)", "fr-FR"},
      {"German (Germany)", "de-DE"},
      {"Greek", "el"},
      {"Hebrew", "he"},
      {"Hindi", "hi"},
      {"Hungarian", "hu"},
      {"Indonesian", "id"},
      {"Italian", "it-IT"},
      {"Japanese", "ja"},
      {"Korean", "ko"},
      {"Norwegian", "nb"},
      {"Polish", "pl"},
      {"Portuguese (Brazil)", "pt-BR"},
      {"Portuguese (Portugal)", "pt-PT"},
      {"Romanian", "ro"},
      {"Russian", "ru"},
      {"Slovak", "sk"},
      {"Spanish (Latin America)", "es-419"},
      {"Spanish (Spain)", "es-ES"},
      {"Swedish", "sv"},
      {"Thai", "th"},
      {"Turkish", "tr"},
      {"Ukrainian", "uk"},
      {"Vietnamese", "vi"}
    ]
  end

  @doc """
  Returns a list of `{label, value}` tuples for IANA timezone identifiers,
  grouped by region prefix. Labels include the standard UTC offset (DST not
  reflected).
  """
  def timezone_options do
    [
      # Africa
      {"Africa/Abidjan (UTC+0)", "Africa/Abidjan"},
      {"Africa/Cairo (UTC+2)", "Africa/Cairo"},
      {"Africa/Casablanca (UTC+0)", "Africa/Casablanca"},
      {"Africa/Johannesburg (UTC+2)", "Africa/Johannesburg"},
      {"Africa/Lagos (UTC+1)", "Africa/Lagos"},
      {"Africa/Nairobi (UTC+3)", "Africa/Nairobi"},
      # America
      {"America/Anchorage (UTC-9)", "America/Anchorage"},
      {"America/Argentina/Buenos_Aires (UTC-3)", "America/Argentina/Buenos_Aires"},
      {"America/Bogota (UTC-5)", "America/Bogota"},
      {"America/Caracas (UTC-4)", "America/Caracas"},
      {"America/Chicago (UTC-6)", "America/Chicago"},
      {"America/Denver (UTC-7)", "America/Denver"},
      {"America/Halifax (UTC-4)", "America/Halifax"},
      {"America/Lima (UTC-5)", "America/Lima"},
      {"America/Los_Angeles (UTC-8)", "America/Los_Angeles"},
      {"America/Mexico_City (UTC-6)", "America/Mexico_City"},
      {"America/New_York (UTC-5)", "America/New_York"},
      {"America/Phoenix (UTC-7)", "America/Phoenix"},
      {"America/Santiago (UTC-4)", "America/Santiago"},
      {"America/Sao_Paulo (UTC-3)", "America/Sao_Paulo"},
      {"America/Toronto (UTC-5)", "America/Toronto"},
      {"America/Vancouver (UTC-8)", "America/Vancouver"},
      {"America/Winnipeg (UTC-6)", "America/Winnipeg"},
      # Asia
      {"Asia/Bangkok (UTC+7)", "Asia/Bangkok"},
      {"Asia/Colombo (UTC+5:30)", "Asia/Colombo"},
      {"Asia/Dubai (UTC+4)", "Asia/Dubai"},
      {"Asia/Hong_Kong (UTC+8)", "Asia/Hong_Kong"},
      {"Asia/Jakarta (UTC+7)", "Asia/Jakarta"},
      {"Asia/Jerusalem (UTC+2)", "Asia/Jerusalem"},
      {"Asia/Karachi (UTC+5)", "Asia/Karachi"},
      {"Asia/Kolkata (UTC+5:30)", "Asia/Kolkata"},
      {"Asia/Kuala_Lumpur (UTC+8)", "Asia/Kuala_Lumpur"},
      {"Asia/Manila (UTC+8)", "Asia/Manila"},
      {"Asia/Riyadh (UTC+3)", "Asia/Riyadh"},
      {"Asia/Seoul (UTC+9)", "Asia/Seoul"},
      {"Asia/Shanghai (UTC+8)", "Asia/Shanghai"},
      {"Asia/Singapore (UTC+8)", "Asia/Singapore"},
      {"Asia/Taipei (UTC+8)", "Asia/Taipei"},
      {"Asia/Tehran (UTC+3:30)", "Asia/Tehran"},
      {"Asia/Tokyo (UTC+9)", "Asia/Tokyo"},
      # Atlantic
      {"Atlantic/Azores (UTC-1)", "Atlantic/Azores"},
      {"Atlantic/Cape_Verde (UTC-1)", "Atlantic/Cape_Verde"},
      # Australia
      {"Australia/Adelaide (UTC+9:30)", "Australia/Adelaide"},
      {"Australia/Brisbane (UTC+10)", "Australia/Brisbane"},
      {"Australia/Melbourne (UTC+10)", "Australia/Melbourne"},
      {"Australia/Perth (UTC+8)", "Australia/Perth"},
      {"Australia/Sydney (UTC+10)", "Australia/Sydney"},
      # Europe
      {"Europe/Amsterdam (UTC+1)", "Europe/Amsterdam"},
      {"Europe/Athens (UTC+2)", "Europe/Athens"},
      {"Europe/Berlin (UTC+1)", "Europe/Berlin"},
      {"Europe/Brussels (UTC+1)", "Europe/Brussels"},
      {"Europe/Bucharest (UTC+2)", "Europe/Bucharest"},
      {"Europe/Budapest (UTC+1)", "Europe/Budapest"},
      {"Europe/Copenhagen (UTC+1)", "Europe/Copenhagen"},
      {"Europe/Dublin (UTC+0)", "Europe/Dublin"},
      {"Europe/Helsinki (UTC+2)", "Europe/Helsinki"},
      {"Europe/Istanbul (UTC+3)", "Europe/Istanbul"},
      {"Europe/Kiev (UTC+2)", "Europe/Kiev"},
      {"Europe/Lisbon (UTC+0)", "Europe/Lisbon"},
      {"Europe/London (UTC+0)", "Europe/London"},
      {"Europe/Madrid (UTC+1)", "Europe/Madrid"},
      {"Europe/Moscow (UTC+3)", "Europe/Moscow"},
      {"Europe/Oslo (UTC+1)", "Europe/Oslo"},
      {"Europe/Paris (UTC+1)", "Europe/Paris"},
      {"Europe/Prague (UTC+1)", "Europe/Prague"},
      {"Europe/Rome (UTC+1)", "Europe/Rome"},
      {"Europe/Stockholm (UTC+1)", "Europe/Stockholm"},
      {"Europe/Vienna (UTC+1)", "Europe/Vienna"},
      {"Europe/Warsaw (UTC+1)", "Europe/Warsaw"},
      {"Europe/Zurich (UTC+1)", "Europe/Zurich"},
      # Pacific
      {"Pacific/Auckland (UTC+12)", "Pacific/Auckland"},
      {"Pacific/Fiji (UTC+12)", "Pacific/Fiji"},
      {"Pacific/Guam (UTC+10)", "Pacific/Guam"},
      {"Pacific/Honolulu (UTC-10)", "Pacific/Honolulu"},
      {"Pacific/Noumea (UTC+11)", "Pacific/Noumea"},
      # UTC
      {"UTC (UTC+0)", "UTC"}
    ]
  end
end
