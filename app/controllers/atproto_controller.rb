class AtprotoController < ApplicationController
  def client_metadata
    render json: {
      client_id: production_oauth_client_id,
      application_type: "web",
      grant_types: [ "authorization_code", "refresh_token" ],
      scope: [ "atproto", "transition:generic" ].join(" "),
      response_type: [ "code" ], # TODO: might need to be plural
      redirect_uris: [ production_oauth_redirect_uri ],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      dpop_bound_access_tokens: true,
      jwks: {
        keys: [ public_key_jwk ]
      }
    }
  end

  private

  def production_oauth_client_id
    "https://local.blueskycounter.com/auth/atproto/client-metadata.json"
  end

  def production_oauth_redirect_uri
    "https://local.blueskycounter.com/auth/atproto/callback"
  end

  def public_key_jwk
    create_ecdsa_public_key_jwk_with_id(key_pair[:public_key], key_pair[:id])
  end

  def create_ecdsa_public_key_jwk_with_id(public_key, id)
    # Extract coordinates from EC public key
    point = public_key.public_key.to_bn
    group = public_key.group
    point = OpenSSL::PKey::EC::Point.new(group, point)

    # Get x,y coordinates in binary
    encoded_point = point.to_octet_string(:uncompressed)
    x_bin = encoded_point[1..32]
    y_bin = encoded_point[33..64]

    # Base64URL encode coordinates
    x = Base64.urlsafe_encode64(x_bin, padding: false)
    y = Base64.urlsafe_encode64(y_bin, padding: false)

    jwk = {
      kid: id,
      kty: "EC",
      crv: "P-256",
      x: x,
      y: y,
      use: "sig"
    }
    jwk
  end

  def key_pair
    private_key_base64 = Rails.application.credentials.dig(:atproto, :private_key)
    public_key_base64 = Rails.application.credentials.dig(:atproto, :public_key)
    key_pair_id = Rails.application.credentials.dig(:atproto, :key_pair_id)

    raise "Missing ATProto credentials." if private_key_base64.blank? || public_key_base64.blank? || key_pair_id.blank?

    private_key = OpenSSL::PKey::EC.new(Base64.decode64(private_key_base64))
    public_key = OpenSSL::PKey::EC.new(Base64.decode64(public_key_base64))

    {
      private_key: private_key,
      public_key: public_key,
      id: key_pair_id
    }
  end
end
