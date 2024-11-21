class AtprotoController < ApplicationController
  def client_metadata
    key_pair = get_oauth_key_pair
    return head :not_found if key_pair.nil?

    Rails.logger.debug "Creating client metadata with key_pair:"
    Rails.logger.debug "  Public key class: #{key_pair[:public_key].class}"
    Rails.logger.debug "  Key pair ID: #{key_pair[:id]}"

    public_key_jwk = create_ecdsa_public_key_jwk_with_id(key_pair[:public_key], key_pair[:id])
    Rails.logger.debug "Generated public key JWK: #{public_key_jwk.inspect}"

    response = {
      client_id: production_oauth_client_id,
      application_type: "web",
      grant_types: [ "authorization_code", "refresh_token" ],
      scope: [ "atproto", "transition:generic" ].join(" "),
      response_type: [ "code" ],
      redirect_uris: [ production_oauth_redirect_uri ],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      dpop_bound_access_tokens: true,
      jwks: {
        keys: [ public_key_jwk ]
      }
    }

    Rails.logger.debug "Full client metadata response: #{response.inspect}"

    render json: response
  end

  private

  def get_oauth_key_pair
    private_key_base64 = Rails.application.credentials.dig(:atproto, :private_key)
    public_key_base64 = Rails.application.credentials.dig(:atproto, :public_key)
    key_pair_id = Rails.application.credentials.dig(:atproto, :key_pair_id)

    return nil if private_key_base64.nil? || public_key_base64.nil? || key_pair_id.nil?

    {
      public_key: Base64.decode64(public_key_base64),
      private_key: Base64.decode64(private_key_base64),
      id: key_pair_id
    }
  end

  def create_ecdsa_public_key_jwk_with_id(public_key, id)
    key = OpenSSL::PKey::EC.new(public_key)
    jwk = JWT::JWK.new(key)

    # Merge the base JWK with our additional parameters
    jwk.export.merge({
      kid: id,
      use: "sig"
    })
  end

  def production_oauth_client_id
    raise "Public URL not defined" if public_url.nil?

    URI.join(public_url, "/auth/atproto/client-metadata.json").to_s
  end

  def production_oauth_redirect_uri
    raise "Public URL not defined" if public_url.nil?

    URI.join(public_url, "/auth/atproto/callback").to_s
  end

  def public_url
    "https://local.blueskycounter.com"
  end
end
