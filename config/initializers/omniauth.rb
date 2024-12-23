require "omniauth/strategies/atproto"

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :atproto, {
    client_id: "https://local.blueskycounter.com/auth/atproto/client-metadata.json",
    client_options: {
      site: "https://local.blueskycounter.com"
    }
  }
end

# Allow both GET and POST while we debug
OmniAuth.config.allowed_request_methods = [ :get, :post ]

# We'll add CSRF protection later
# OmniAuth.config.request_validation_phase = ActionController::RequestForgeryProtection::ProtectionMethods::ExceptionOnInvalidAuthenticityToken
