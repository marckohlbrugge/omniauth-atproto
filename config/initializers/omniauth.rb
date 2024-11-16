require "omniauth/strategies/atproto"

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :atproto, {
    client_options: {
      site: "https://local.blueskycounter.com"
    }
  }
end

# FIXME: Not sure this is needed
OmniAuth.config.allowed_request_methods = [ :post, :get ]
