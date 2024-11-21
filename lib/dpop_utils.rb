require "jwt_utils"

module DPoPUtils
  def self.create_client_assertion(key_pair, client_id, issuer)
    Rails.logger.debug "Creating client assertion with:"
    Rails.logger.debug "  client_id: #{client_id}"
    Rails.logger.debug "  issuer: #{issuer}"
    Rails.logger.debug "  key_pair type: #{key_pair.class}"
    Rails.logger.debug "  key_pair group: #{key_pair.group.curve_name}"

    raise ArgumentError, "key_pair must be an OpenSSL::PKey::EC" unless key_pair.is_a?(OpenSSL::PKey::EC)
    raise ArgumentError, "client_id is required" if client_id.nil? || client_id.empty?
    raise ArgumentError, "issuer is required" if issuer.nil? || issuer.empty?
    raise ArgumentError, "key_pair must have a private key" unless key_pair.private_key?

    # Create JWK for the key
    jwk = JWT::JWK.new(key_pair)
    public_jwk = jwk.export.merge({
      kid: "banana",  # Use the same kid as in client metadata
      use: "sig"
    })

    Rails.logger.debug "Created JWK:"
    Rails.logger.debug "  Public JWK: #{public_jwk}"

    # Create JWT headers
    headers = {
      typ: "JWT",
      alg: "ES256",
      kid: "banana"  # Use the same kid as in client metadata
    }

    Rails.logger.debug "JWT headers: #{headers}"

    issued_at = Time.now.to_i

    # Create JWT payload
    payload = {
      iss: client_id,
      sub: client_id,
      aud: issuer,
      jti: SecureRandom.uuid,
      iat: issued_at,
      exp: issued_at + 300  # 5 minutes
    }

    Rails.logger.debug "JWT payload: #{payload}"

    # Sign the JWT
    token = JWT.encode(payload, key_pair, "ES256", headers)
    Rails.logger.debug "Generated client assertion token: #{token[0..32]}..."
    token
  end

  def self.create_dpop(key_pair, request_method, request_url, nonce = nil, attributes = {})
    Rails.logger.debug "Creating DPoP token with:"
    Rails.logger.debug "  Method: #{request_method}"
    Rails.logger.debug "  URL: #{request_url}"
    Rails.logger.debug "  Nonce: #{nonce}"
    Rails.logger.debug "  Attributes: #{attributes}"
    Rails.logger.debug "  Key pair type: #{key_pair&.class}"
    Rails.logger.debug "  Key pair group: #{key_pair&.group&.curve_name}"

    raise ArgumentError, "request_method is required" if request_method.nil? || request_method.empty?
    raise ArgumentError, "request_url is required" if request_url.nil? || request_url.empty?
    raise ArgumentError, "request_url must be a valid URL" unless request_url =~ URI.regexp
    raise ArgumentError, "attributes must be a hash" unless attributes.is_a?(Hash)

    # Get the base URL without query parameters
    base_url = begin
      uri = URI.parse(request_url)
      url = "#{uri.scheme}://#{uri.host}#{uri.path}"
      Rails.logger.debug "Parsed base URL: #{url}"
      url
    rescue URI::InvalidURIError => e
      raise ArgumentError, "Invalid URL format: #{e.message}"
    end

    # Create base payload
    payload = {
      jti: SecureRandom.uuid,
      htm: request_method,
      htu: base_url,  # Use the cleaned URL
      iat: Time.now.to_i,
      exp: Time.now.to_i + 300
    }

    # Add nonce if provided
    payload[:nonce] = nonce if nonce

    # Merge any additional attributes
    payload.merge!(attributes)

    Rails.logger.debug "DPoP payload before signing: #{payload}"

    # Get the key pair from credentials if not provided
    if key_pair.nil?
      Rails.logger.debug "No key pair provided, fetching from credentials"
      private_key_base64 = Rails.application.credentials.dig(:atproto, :private_key)
      raise ArgumentError, "No key pair provided and none found in credentials" if private_key_base64.nil?

      Rails.logger.debug "Found private key in credentials (first 10 chars): #{private_key_base64[0..10]}..."
      key_pair = OpenSSL::PKey::EC.new(Base64.decode64(private_key_base64))
      Rails.logger.debug "Created key pair from credentials"
      Rails.logger.debug "  Type: #{key_pair.class}"
      Rails.logger.debug "  Group: #{key_pair.group.curve_name}"
      Rails.logger.debug "  Private key? #{key_pair.private_key?}"
    end

    raise ArgumentError, "key_pair must be an OpenSSL::PKey::EC" unless key_pair.is_a?(OpenSSL::PKey::EC)
    raise ArgumentError, "key_pair must have a private key" unless key_pair.private_key?

    # Create JWK from key pair
    jwk = JWT::JWK.new(key_pair)
    public_jwk = jwk.export.merge({
      kid: key_pair.public_key.to_bn.to_s(2),
      use: "sig"
    })

    Rails.logger.debug "Created JWK for DPoP:"
    Rails.logger.debug "  Public JWK: #{public_jwk}"

    # Create headers with public key JWK
    headers = {
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: public_jwk
    }

    Rails.logger.debug "DPoP headers: #{headers}"

    # Create and sign the JWT
    token = JWT.encode(payload, key_pair, "ES256", headers)
    Rails.logger.debug "Generated DPoP token (first 32 chars): #{token[0..32]}..."
    token
  end

  private

  def self.create_public_jwk(key_pair)
    Rails.logger.debug "Creating public JWK from key pair:"
    Rails.logger.debug "  Type: #{key_pair.class}"
    Rails.logger.debug "  Group: #{key_pair.group.curve_name}"

    raise ArgumentError, "key_pair must be an OpenSSL::PKey::EC" unless key_pair.is_a?(OpenSSL::PKey::EC)

    # Get the public key point
    point = key_pair.public_key
    bn = point.to_bn

    Rails.logger.debug "Public key point:"
    Rails.logger.debug "  BN: #{bn.to_s(16)[0..32]}..."

    # Convert to octet string and split into x and y coordinates
    oct = bn.to_s(2)  # Get binary representation
    coord_len = oct.length / 2
    x_coord = oct[0, coord_len]
    y_coord = oct[coord_len, coord_len]

    Rails.logger.debug "Coordinates:"
    Rails.logger.debug "  Length: #{coord_len}"
    Rails.logger.debug "  X (first 32 chars): #{x_coord[0..32]}..."
    Rails.logger.debug "  Y (first 32 chars): #{y_coord[0..32]}..."

    # Create JWK with only public components
    jwk = {
      kty: "EC",
      crv: "P-256",
      x: Base64.urlsafe_encode64(x_coord, padding: false),
      y: Base64.urlsafe_encode64(y_coord, padding: false)
    }

    Rails.logger.debug "Generated public JWK: #{jwk}"
    jwk
  end
end
