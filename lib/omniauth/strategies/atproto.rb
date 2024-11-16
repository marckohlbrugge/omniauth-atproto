require "omniauth-oauth2"
require "faraday"
require "jwt"

module OmniAuth
  module Strategies
    class Atproto < OmniAuth::Strategies::OAuth2
      option :name, "atproto"

      option :client_options, {
        site: nil,
        authorize_url: nil,
        token_url: nil
      }

      def request_phase
        # Check if handle parameter is present
        unless request.params["handle"]
          fail!(:missing_handle, OmniAuth::Error.new("Handle parameter is required"))
          return
        end

        handle = request.params["handle"]
        did = resolve_handle(handle)
        pds_endpoint = get_pds_from_did(did)
        auth_server = get_authorization_server(pds_endpoint)
        auth_metadata = get_auth_server_metadata(auth_server)

        # Update client options with discovered endpoints
        options.client_options.site = auth_metadata[:issuer]
        options.client_options.authorize_url = auth_metadata[:authorization_endpoint]
        options.client_options.token_url = auth_metadata[:token_endpoint]

        # Set up PKCE
        code_verifier = SecureRandom.urlsafe_base64(64)
        code_challenge = generate_code_challenge(code_verifier)

        session["omniauth.code_verifier"] = code_verifier
        session["omniauth.did"] = did

        # Create client_id with redirect_uri and scope
        client_id = "https://local.blueskycounter.com/auth/atproto/client-metadata.json"

        options.client_id = client_id
        Rails.logger.debug "Request phase client_id: #{client_id}"

        # Add PKCE parameters to the authorization request
        options.authorize_params.code_challenge = code_challenge
        options.authorize_params.code_challenge_method = "S256"

        options.authorize_params.scope = "atproto transition:generic"

        super
      end

      def callback_phase
        if request.params["error"]
          fail!(request.params["error"], CallbackError.new(request.params["error"], request.params["error_description"]))
        elsif !request.params["code"]
          fail!(:missing_code, OmniAuth::Error.new("No code parameter in callback request"))
        else
          begin
            # Get stored values from session
            code_verifier = session.delete("omniauth.code_verifier")
            did = session.delete("omniauth.did")

            # Get token endpoint from auth server metadata, just like TypeScript
            pds_endpoint = get_pds_from_did(did)
            auth_server = get_authorization_server(pds_endpoint)
            auth_metadata = get_auth_server_metadata(auth_server)
            options.client_options.token_url = auth_metadata[:token_endpoint]

            # Generate DPoP key pair
            dpop_key_pair = generate_dpop_key_pair

            # Exchange code for tokens
            tokens = exchange_code_for_tokens(
              request.params["code"],
              code_verifier,
              dpop_key_pair
            )

            # Verify DID matches
            if tokens[:did] != did
              fail!(:did_mismatch, CallbackError.new(:did_mismatch, "DID mismatch"))
              return
            end

            # Fetch user profile
            profile = fetch_user_profile(tokens[:access_token], tokens[:did], dpop_key_pair)

            # Build auth hash
            @auth_hash = build_auth_hash(tokens, profile, dpop_key_pair)

            super
          rescue StandardError => e
            fail!(:invalid_credentials, e)
          end
        end
      end

      private

      def resolve_handle(handle)
        # Try DNS TXT record first
        txt_response = Faraday.get(
          "https://cloudflare-dns.com/dns-query",
          { name: "_atproto.#{handle}", type: "TXT" },
          { "Accept" => "application/dns-json" }
        )

        if txt_response.success?
          result = JSON.parse(txt_response.body)
          if answer = result["Answer"]&.first
            record = answer["data"]
            return parse_txt_dns_record(record)
          end
        end

        # Fallback to well-known endpoint
        wellknown_response = Faraday.get("https://#{handle}/.well-known/atproto-did")
        return wellknown_response.body if wellknown_response.success?

        raise "Failed to resolve handle"
      end

      def get_pds_from_did(did)
        if did.start_with?("did:plc:")
          get_pds_from_plc_did(did)
        elsif did.start_with?("did:web:")
          get_pds_from_web_did(did)
        else
          raise "Unknown DID format"
        end
      end

      def get_authorization_server(pds_endpoint)
        response = Faraday.get("#{pds_endpoint}/.well-known/oauth-protected-resource")
        raise "Failed to get PDS authorization server" unless response.success?

        result = JSON.parse(response.body)
        result.dig("authorization_servers", 0) or raise "No authorization server found"
      end

      def get_auth_server_metadata(issuer)
        response = Faraday.get("#{issuer}/.well-known/oauth-authorization-server")
        raise "Failed to get authorization server metadata" unless response.success?

        result = JSON.parse(response.body)
        raise "Invalid metadata" unless result["issuer"] == issuer

        {
          issuer:,
          pushed_authorization_request_endpoint: result["pushed_authorization_request_endpoint"],
          token_endpoint: result["token_endpoint"],
          authorization_endpoint: result["authorization_endpoint"]
        }
      end

      def generate_code_challenge(verifier)
        Base64.urlsafe_encode64(
          Digest::SHA256.digest(verifier),
          padding: false
        )
      end

      def parse_txt_dns_record(record)
        return unless record.start_with?('"') && record.end_with?('"')

        key_value = record[1..-2] # Remove surrounding quotes
        key, value = key_value.split("=")

        raise "Invalid record format" unless key == "did"
        value
      end

      def get_pds_from_plc_did(did)
        response = Faraday.get("https://plc.directory/#{did}")
        raise "Invalid DID" unless response.success?

        result = JSON.parse(response.body)
        find_pds_service_endpoint(result["service"])
      end

      def get_pds_from_web_did(did)
        prefix = "did:web:"
        raise "Invalid Web DID" unless did.start_with?(prefix)

        target = did[prefix.length..]
        target = target.gsub(":", "/")
        target = URI.decode_www_form_component(target)

        response = Faraday.get("https://#{target}/.well-known/did.json")
        raise "Invalid DID" unless response.success?

        result = JSON.parse(response.body)
        find_pds_service_endpoint(result["service"])
      end

      def find_pds_service_endpoint(services)
        service = Array(services).find { |s| s["id"] == "#atproto_pds" }
        service&.fetch("serviceEndpoint") or raise "Failed to get PDS"
      end

      def exchange_code_for_tokens(code, code_verifier, dpop_key_pair)
        private_key_base64 = Rails.application.credentials.dig(:atproto, :private_key)
        key_pair_id = Rails.application.credentials.dig(:atproto, :key_pair_id)
        private_key = OpenSSL::PKey::EC.new(Base64.decode64(private_key_base64))

        client_id = "https://local.blueskycounter.com/auth/atproto/client-metadata.json"

        client_assertion = create_client_assertion(
          client_id,
          options.client_options.site,
          private_key,
          key_pair_id
        )

        body = {
          grant_type: "authorization_code",
          client_id: client_id,
          code: code,
          code_verifier: code_verifier,
          redirect_uri: callback_url,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: client_assertion
        }

        response = client.auth_code.get_token(
          code,
          body.merge(
            headers: {
              "Content-Type" => "application/x-www-form-urlencoded",
              "Accept" => "application/json",
              "DPoP" => generate_dpop_token(dpop_key_pair, "POST", options.client_options.token_url)
            }
          )
        )

        {
          access_token: response.token,
          refresh_token: response.refresh_token,
          expires_at: response.expires_at,
          did: response.params["sub"]
        }
      end

      def fetch_user_profile(access_token, did, dpop_key_pair)
        pds_endpoint = get_pds_from_did(did)
        url = "#{pds_endpoint}/xrpc/app.bsky.actor.getProfile?actor=#{did}"

        request = Faraday::Request.new do |req|
          req.url url
          req.headers["Authorization"] = "DPoP #{access_token}"
          req.headers["DPoP"] = generate_dpop_token(dpop_key_pair, "GET", url)
        end

        response, _nonce = handle_oauth_request(request, dpop_key_pair)

        raise "Failed to fetch profile" unless response.success?
        JSON.parse(response.body)
      end

      def build_auth_hash(tokens, profile, dpop_key_pair)
        OmniAuth::Utils.deep_merge(super(), {
          "uid" => tokens[:did],
          "credentials" => {
            "token" => tokens[:access_token],
            "refresh_token" => tokens[:refresh_token],
            "expires_at" => tokens[:expires_at],
            "expires" => true
          },
          "info" => {
            "did" => tokens[:did],
            "handle" => profile["handle"],
            "display_name" => profile["displayName"],
            "description" => profile["description"],
            "avatar" => profile.dig("avatar", "url"),
            "dpop_key" => export_dpop_key(dpop_key_pair)
          },
          "extra" => {
            "raw_info" => profile
          }
        })
      end

      def generate_dpop_key_pair
        OpenSSL::PKey::EC.generate("prime256v1")
      end

      def generate_dpop_token(key_pair, method, url, nonce = nil)
        # Generate random bytes for jti
        jti_bytes = SecureRandom.random_bytes(20)
        jti = Base64.urlsafe_encode64(jti_bytes, padding: false)

        # Create header with public key JWK
        header = {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: create_public_key_jwk(key_pair)
        }

        # Create payload
        payload = {
          jti: jti,
          htm: method,
          htu: url.split("?")[0],
          iat: Time.now.to_i
        }
        payload[:nonce] = nonce if nonce

        # Convert to JSON and encode
        header_json = header.to_json
        payload_json = payload.to_json

        encoded_header = Base64.urlsafe_encode64(header_json, padding: false)
        encoded_payload = Base64.urlsafe_encode64(payload_json, padding: false)

        # Create signature input (matches createJWTSignatureMessage)
        message = "#{encoded_header}.#{encoded_payload}"

        # Sign using SHA256 digest
        digest = OpenSSL::Digest.new("sha256")
        signature = key_pair.sign(digest, message)

        # Encode signature
        encoded_signature = Base64.urlsafe_encode64(signature, padding: false)

        # Return complete JWT
        "#{message}.#{encoded_signature}"
      end

      def export_dpop_key(key_pair)
        {
          private_key: key_pair.to_pem,
          public_key: key_pair.public_key.to_pem
        }.to_json
      end

      private

      def create_public_key_jwk(key_pair)
        pub_key_bn = key_pair.public_key.to_bn
        pub_key_hex = pub_key_bn.to_s(16)

        # Extract x and y coordinates (skip the 0x04 prefix)
        x_hex = pub_key_hex[2, 64]
        y_hex = pub_key_hex[66, 64]

        {
          kty: "EC",
          crv: "P-256",
          x: Base64.urlsafe_encode64([ x_hex ].pack("H*"), padding: false),
          y: Base64.urlsafe_encode64([ y_hex ].pack("H*"), padding: false)
        }
      end

      def refresh_access_token(refresh_token, dpop_key_pair, dpop_nonce = nil)
        response = client.get_token(
          grant_type: "refresh_token",
          refresh_token:,
          headers: {
            "DPoP" => generate_dpop_token(dpop_key_pair, "POST", options.client_options.token_url, dpop_nonce)
          }
        )

        {
          access_token: response.token,
          refresh_token: response.refresh_token,
          expires_at: response.expires_at,
          did: response.params["sub"]
        }
      end

      def handle_oauth_request(request, dpop_key_pair, dpop_nonce = nil)
        response = request.execute
        new_nonce = response.headers["DPoP-Nonce"]

        if response.status == 401 && response.headers["WWW-Authenticate"]&.start_with?("DPoP")
          # Retry with new nonce if provided
          if new_nonce
            request.headers["DPoP"] = generate_dpop_token(dpop_key_pair, request.method, request.url, new_nonce)
            response = request.execute
          end
        end

        [ response, new_nonce ]
      end

      def create_client_assertion(client_id, auth_server_issuer, private_key, key_pair_id)
        header = {
          typ: "JWT",
          alg: "ES256",
          kid: key_pair_id
        }

        issued_at = Time.now.to_i
        payload = {
          iss: client_id,
          sub: client_id,
          aud: auth_server_issuer,
          jti: SecureRandom.base64(20),
          iat: issued_at,
          exp: issued_at + 60
        }

        JWT.encode(payload, private_key, "ES256", header)
      end
    end
  end
end
