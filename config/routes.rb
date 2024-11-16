Rails.application.routes.draw do
  get "pages/home"
  get "/auth/atproto/client-metadata.json", to: "atproto#client_metadata"
  get "/auth/:provider/callback", to: "sessions#create"
  get "/auth/failure", to: "sessions#failure"

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  root "pages#home"
end
