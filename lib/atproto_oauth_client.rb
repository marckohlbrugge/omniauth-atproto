require "dpop_utils"

class ATProtoOAuthClient
  attr_reader :authorization_server_issuer, :client_id, :redirect_uri, :dpop_key_pair

  def initialize(authorization_server_issuer, client_id, redirect_uri, key_pair)
    Rails.logger.debug "Initializing ATProtoOAuthClient with:"
    Rails.logger.debug "  authorization_server_issuer: #{authorization_server_issuer}"
    Rails.logger.debug "  client_id: #{client_id}"
    Rails.logger.debug "  redirect_uri: #{redirect_uri}"
    Rails.logger.debug "  key_pair type: #{key_pair.class}"

    raise ArgumentError, "authorization_server_issuer is required" if authorization_server_issuer.nil? || authorization_server_issuer.empty?
    raise ArgumentError, "client_id is required" if client_id.nil? || client_id.empty?
    raise ArgumentError, "redirect_uri is required" if redirect_uri.nil? || redirect_uri.empty?
    raise ArgumentError, "key_pair is required" if key_pair.nil?

    @authorization_server_issuer = authorization_server_issuer
    @client_id = client_id
    @redirect_uri = redirect_uri

    # Set up token URL based on the issuer
    @token_url = URI.join(authorization_server_issuer, "/oauth/token").to_s
    Rails.logger.debug "Token URL: #{@token_url}"

    if key_pair.is_a?(String)
      Rails.logger.debug "Converting base64 key_pair string to OpenSSL::PKey::EC"
      decoded = Base64.decode64(key_pair)
      Rails.logger.debug "Decoded key length: #{decoded.length} bytes"
      @dpop_key_pair = OpenSSL::PKey::EC.new(decoded)
      Rails.logger.debug "Successfully initialized key pair:"
      Rails.logger.debug "  Type: #{@dpop_key_pair.class}"
      Rails.logger.debug "  Group: #{@dpop_key_pair.group.curve_name}"
      Rails.logger.debug "  Private key? #{@dpop_key_pair.private_key?}"
    else
      @dpop_key_pair = key_pair
    end

    # Convert the public key point to a byte string
    point_hex = @dpop_key_pair.public_key.to_bn.to_s(16)
    # Remove the '04' prefix (uncompressed point indicator)
    point_hex = point_hex[2..-1] if point_hex.start_with?("04")
    # Split into x and y coordinates (each 64 chars in hex = 32 bytes)
    x_hex = point_hex[0...64]
    y_hex = point_hex[64..-1]

    # Convert hex to binary
    x_bin = [ x_hex ].pack("H*")
    y_bin = [ y_hex ].pack("H*")

    # Generate the JWK representation
    @jwk = {
      kty: "EC",
      crv: "P-256",
      x: Base64.urlsafe_encode64(x_bin, padding: false),
      y: Base64.urlsafe_encode64(y_bin, padding: false),
      kid: "banana",
      use: "sig"
    }
  end

  def self.create_localhost_client(authorization_server_issuer, redirect_uri, allowed_optional_scopes)
    Rails.logger.debug "Creating localhost client with:"
    Rails.logger.debug "  authorization_server_issuer: #{authorization_server_issuer}"
    Rails.logger.debug "  redirect_uri: #{redirect_uri}"
    Rails.logger.debug "  allowed_optional_scopes: #{allowed_optional_scopes.inspect}"

    raise ArgumentError, "authorization_server_issuer is required" if authorization_server_issuer.nil? || authorization_server_issuer.empty?
    raise ArgumentError, "redirect_uri is required" if redirect_uri.nil? || redirect_uri.empty?
    raise ArgumentError, "allowed_optional_scopes must be an array" unless allowed_optional_scopes.is_a?(Array)

    client_id_params = {
      redirect_uri: redirect_uri,
      scope: [ "atproto", *allowed_optional_scopes ].join(" ")
    }
    client_id = "http://localhost?" + URI.encode_www_form(client_id_params)

    Rails.logger.debug "Generated client_id: #{client_id}"

    new(authorization_server_issuer, client_id, redirect_uri, nil)
  end

  def validate_authorization_code(code, code_verifier, issuer = nil, state = nil)
    Rails.logger.debug "Validating authorization code with:"
    Rails.logger.debug "  code: #{code}"
    Rails.logger.debug "  code_verifier: #{code_verifier}"
    Rails.logger.debug "  issuer: #{issuer}"
    Rails.logger.debug "  state: #{state}"
    Rails.logger.debug "  token_url: #{@token_url}"

    # Generate DPoP proof
    jti = SecureRandom.uuid
    iat = Time.now.to_i
    htm = "POST"
    htu = @token_url

    header = {
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: @jwk
    }

    payload = {
      jti:,
      iat:,
      htm:,
      htu:
    }

    # Add issuer to payload if provided
    payload[:iss] = issuer if issuer

    # Create the DPoP proof JWT
    unsigned_token = [
      Base64.urlsafe_encode64(JSON.generate(header), padding: false),
      Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
    ].join(".")

    # Sign the token using SHA256 and the EC key
    digest = OpenSSL::Digest::SHA256.new
    signature = @dpop_key_pair.sign(digest, unsigned_token)
    signed_token = "#{unsigned_token}.#{Base64.urlsafe_encode64(signature, padding: false)}"

    # Make the token request
    response = HTTP.headers({
      "DPoP" => signed_token,
      "Content-Type" => "application/x-www-form-urlencoded"
    }).post(@token_url, form: {
      grant_type: "authorization_code",
      code:,
      redirect_uri: @redirect_uri,
      code_verifier:,
      client_id: @client_id
    })

    Rails.logger.debug "Token response status: #{response.status}"
    Rails.logger.debug "Token response body: #{response.body}"

    if response.status.success?
      JSON.parse(response.body.to_s)
    else
      raise "Token request failed: #{response.status} - #{response.body}"
    end
  end

  def make_pds_request(url, method, access_token, dpop_key_pair, dpop_nonce, issuer)
    Rails.logger.debug "Making PDS request with:"
    Rails.logger.debug "  url: #{url}"
    Rails.logger.debug "  method: #{method}"
    Rails.logger.debug "  access_token: #{access_token[0..10]}..."
    Rails.logger.debug "  dpop_nonce: #{dpop_nonce}"
    Rails.logger.debug "  issuer: #{issuer}"

    raise ArgumentError, "url is required" if url.nil? || url.empty?
    raise ArgumentError, "method is required" if method.nil? || method.empty?
    raise ArgumentError, "access_token is required" if access_token.nil? || access_token.empty?
    raise ArgumentError, "dpop_key_pair must be an OpenSSL::PKey::EC" unless dpop_key_pair.is_a?(OpenSSL::PKey::EC)
    raise ArgumentError, "issuer is required" if issuer.nil? || issuer.empty?

    # Create DPoP token with all required fields for PDS endpoints
    dpop_token = DPoPUtils.create_dpop(
      dpop_key_pair,
      method,
      url,
      dpop_nonce,
      {
        access_token:,  # Will be used to generate ath field
        iss: issuer     # Required for PDS endpoints
      }
    )

    raise "Failed to generate DPoP token" if dpop_token.nil? || dpop_token.empty?
    Rails.logger.debug "Generated DPoP token: #{dpop_token[0..32]}..."

    # Make request with both DPoP and Authorization headers
    response = Faraday.new.send(method.downcase) do |req|
      req.url url
      req.headers["DPoP"] = dpop_token
      req.headers["Authorization"] = "DPoP #{access_token}"
    end

    Rails.logger.debug "Initial response status: #{response.status}"
    Rails.logger.debug "Initial response headers: #{response.headers}"

    # Handle nonce refresh if needed
    if response.status == 401 && response.headers["dpop-nonce"]
      new_nonce = response.headers["dpop-nonce"]
      Rails.logger.debug "Retrying with new DPoP nonce: #{new_nonce}"

      dpop_token = DPoPUtils.create_dpop(
        dpop_key_pair,
        method,
        url,
        new_nonce,
        {
          access_token:,
          iss: issuer
        }
      )

      raise "Failed to generate DPoP token with new nonce" if dpop_token.nil? || dpop_token.empty?
      Rails.logger.debug "Generated new DPoP token: #{dpop_token[0..32]}..."

      response = Faraday.new.send(method.downcase) do |req|
        req.url url
        req.headers["DPoP"] = dpop_token
        req.headers["Authorization"] = "DPoP #{access_token}"
      end

      Rails.logger.debug "Retry response status: #{response.status}"
      Rails.logger.debug "Retry response headers: #{response.headers}"
    end

    response
  end

  private

  def make_token_request(token_url, dpop_token, code, code_verifier)
    Rails.logger.debug "Making token request to #{token_url}"

    # Generate client assertion JWT
    client_assertion = create_client_assertion(token_url)
    raise "Failed to generate client assertion" if client_assertion.nil? || client_assertion.empty?
    Rails.logger.debug "Generated client assertion: #{client_assertion[0..32]}..."

    # Strip query parameters from redirect_uri
    clean_redirect_uri = @redirect_uri.split("?").first
    Rails.logger.debug "Clean redirect URI: #{clean_redirect_uri}"

    Faraday.post(token_url) do |req|
      req.headers["DPoP"] = dpop_token
      req.headers["Content-Type"] = "application/x-www-form-urlencoded"
      req.body = URI.encode_www_form({
        grant_type: "authorization_code",
        code:,
        code_verifier:,
        client_id: @client_id,
        redirect_uri: clean_redirect_uri,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion:
      })
      Rails.logger.debug "Request body: #{req.body}"
    end
  end

  def create_client_assertion(token_url)
    Rails.logger.debug "Creating client assertion for token_url: #{token_url}"
    raise ArgumentError, "token_url is required" if token_url.nil? || token_url.empty?

    now = Time.now.to_i

    claims = {
      iss: @client_id,
      sub: @client_id,
      aud: URI.parse(token_url).tap { |uri| uri.path = "" }.to_s,
      jti: SecureRandom.uuid,
      iat: now,
      exp: now + 300
    }

    Rails.logger.debug "Client assertion claims:"
    claims.each do |key, value|
      Rails.logger.debug "  #{key}: #{value}"
    end

    Rails.logger.debug "Creating client assertion with key pair class: #{@dpop_key_pair.class}"
    Rails.logger.debug "Key pair details:"
    Rails.logger.debug "  Group: #{@dpop_key_pair.group.curve_name}"
    Rails.logger.debug "  Private key? #{@dpop_key_pair.private_key?}"
    Rails.logger.debug "  Public key: #{@dpop_key_pair.public_key.to_text[0..64]}..."

    key_pair_id = Rails.application.credentials.dig(:atproto, :key_pair_id)
    raise "Missing key_pair_id in credentials" if key_pair_id.nil?

    header = {
      typ: "jwt",
      alg: "ES256",
      kid: key_pair_id  # Use the same kid as registered
    }

    Rails.logger.debug "JWT header:"
    header.each do |key, value|
      Rails.logger.debug "  #{key}: #{value}"
    end

    JWT.encode(claims, @dpop_key_pair, "ES256", header)
  end
end
