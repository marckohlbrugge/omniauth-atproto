class SessionsController < ApplicationController
  def create
    auth = request.env["omniauth.auth"]
    render json: auth
  rescue StandardError => e
    Rails.logger.error("Bluesky auth error: #{e.message}")
    render json: { error: e.message }, status: :unprocessable_entity
  end

  def failure
    render json: { error: "Authentication failed" }, status: :unauthorized
  end
end
