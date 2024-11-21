require "json/jwt"

module JWTUtils
  def self.encode_base64url_no_padding(data)
    Rails.logger.debug "Encoding data to base64url (no padding):"
    Rails.logger.debug "  Input data type: #{data.class}"
    Rails.logger.debug "  Input data length: #{data.bytesize} bytes"
    raise ArgumentError, "Input data cannot be nil" if data.nil?
    raise ArgumentError, "Input data must be a String" unless data.is_a?(String)

    encoded = Base64.urlsafe_encode64(data, padding: false)
    Rails.logger.debug "  Encoded length: #{encoded.length} chars"
    Rails.logger.debug "  Encoded result: #{encoded[0..32]}..." # Log first part
    encoded
  end

  def self.create_ecdsa_public_key_jwk(key)
    Rails.logger.debug "Creating ECDSA public key JWK:"
    Rails.logger.debug "  Key class: #{key.class}"
    Rails.logger.debug "  Key details:"
    Rails.logger.debug "    Group: #{key.group.curve_name rescue 'N/A'}"
    Rails.logger.debug "    Private key? #{key.private_key? rescue 'N/A'}"
    Rails.logger.debug "    Public key: #{key.public_key.to_text[0..64] rescue 'N/A'}..."

    raise ArgumentError, "Key cannot be nil" if key.nil?
    raise ArgumentError, "Key must be an OpenSSL::PKey::EC" unless key.is_a?(OpenSSL::PKey::EC)
    raise ArgumentError, "Key must have a public key component" unless key.public_key?

    jwk = JSON::JWK.new(key)
    Rails.logger.debug "  Generated JWK:"
    Rails.logger.debug "    kty: #{jwk.to_h['kty']}"
    Rails.logger.debug "    crv: #{jwk.to_h['crv']}"
    Rails.logger.debug "    x: #{jwk.to_h['x']}"
    Rails.logger.debug "    y: #{jwk.to_h['y']}"
    jwk
  end

  def self.create_jwt_signature_message(header_json, payload_json)
    Rails.logger.debug "Creating JWT signature message:"
    Rails.logger.debug "  Header JSON: #{header_json}"
    Rails.logger.debug "  Payload JSON: #{payload_json}"

    raise ArgumentError, "Header JSON cannot be nil" if header_json.nil?
    raise ArgumentError, "Payload JSON cannot be nil" if payload_json.nil?
    raise ArgumentError, "Header must be valid JSON" unless JSON.parse(header_json)
    raise ArgumentError, "Payload must be valid JSON" unless JSON.parse(payload_json)

    header_b64 = encode_base64url_no_padding(header_json)
    payload_b64 = encode_base64url_no_padding(payload_json)

    message = "#{header_b64}.#{payload_b64}"
    Rails.logger.debug "  Generated message: #{message}"
    message
  end

  def self.encode_jwt(header_json, payload_json, signature)
    Rails.logger.debug "Encoding complete JWT:"
    Rails.logger.debug "  Header JSON length: #{header_json.bytesize} bytes"
    Rails.logger.debug "  Payload JSON length: #{payload_json.bytesize} bytes"
    Rails.logger.debug "  Signature length: #{signature.bytesize} bytes"

    raise ArgumentError, "Signature cannot be nil" if signature.nil?
    raise ArgumentError, "Signature must be a String" unless signature.is_a?(String)
    raise ArgumentError, "Signature cannot be empty" if signature.empty?

    message = create_jwt_signature_message(header_json, payload_json)
    signature_b64 = encode_base64url_no_padding(signature)

    jwt = "#{message}.#{signature_b64}"
    Rails.logger.debug "  Final JWT length: #{jwt.length} chars"
    Rails.logger.debug "  Final JWT: #{jwt[0..64]}..." # Log first part
    jwt
  end
end
