require "omniauth-oauth2"
require "faraday"
require "jwt"
require "ostruct"

require "atproto_oauth_client"

module OmniAuth
  module Strategies
    class Atproto < OmniAuth::Strategies::OAuth2
      option :name, "atproto"

      # Enable PKCE
      option :pkce, true

      option :client_options, {
        site: nil,
        authorize_url: nil,
        token_url: nil
      }

      def state
        @state ||= SecureRandom.hex(24)
      end

      def request_phase
        Rails.logger.debug "Starting request phase"
        Rails.logger.debug "Request params: #{request.params.inspect}"

        # Get and validate handle
        unless request.params["handle"]
          Rails.logger.error "Missing required handle parameter"
          fail!(:missing_handle, OmniAuth::Error.new("Handle parameter is required"))
          return
        end
        handle = request.params["handle"]
        Rails.logger.debug "Using handle: #{handle}"

        begin
          # Follow the exact same flow as TypeScript
          Rails.logger.debug "Resolving handle to DID..."
          did = resolve_atproto_handle(handle)
          raise "Failed to get valid DID" if did.nil? || did.empty?
          Rails.logger.debug "Resolved DID: #{did}"

          Rails.logger.debug "Getting PDS endpoint from DID..."
          pds_endpoint = get_pds_from_account_did(did)
          raise "Failed to get valid PDS endpoint" if pds_endpoint.nil? || pds_endpoint.empty?
          Rails.logger.debug "Found PDS endpoint: #{pds_endpoint}"

          Rails.logger.debug "Getting authorization server from PDS..."
          auth_server = get_authorization_server(pds_endpoint)
          raise "Failed to get valid auth server" if auth_server.nil? || auth_server.empty?
          Rails.logger.debug "Found auth server: #{auth_server}"

          Rails.logger.debug "Getting authorization server metadata..."
          auth_metadata = get_atproto_authorization_server_metadata(auth_server)
          raise "Missing required metadata fields" unless auth_metadata[:issuer] &&
                                                       auth_metadata[:token_endpoint] &&
                                                       auth_metadata[:authorization_endpoint]
          Rails.logger.debug "Auth metadata: #{auth_metadata}"

          # Generate PKCE values before storing in session
          Rails.logger.debug "Generating PKCE values..."
          code_verifier = SecureRandom.urlsafe_base64(64).tr("lIO0", "sxyz")
          Rails.logger.debug "Generated code verifier: #{code_verifier}"

          Rails.logger.debug "Generating code challenge from verifier"
          code_challenge = Base64.urlsafe_encode64(
            OpenSSL::Digest::SHA256.digest(code_verifier),
            padding: false
          )
          Rails.logger.debug "Generated code challenge: #{code_challenge}"

          # Store values in session
          Rails.logger.debug "Storing values in session..."
          session["omniauth.state"] = state
          session["omniauth.issuer"] = auth_metadata[:issuer]
          session["omniauth.did"] = did
          session["omniauth.pkce.code_verifier"] = code_verifier
          session["omniauth.client_id"] = options.client_id || options.client_options[:client_id]
          Rails.logger.debug "Stored client_id in session: #{session['omniauth.client_id']}"

          # Ensure PKCE code verifier is stored in session
          Rails.logger.debug "Generating PKCE values..."
          code_verifier = SecureRandom.urlsafe_base64(64)
          raise "Failed to generate code verifier" if code_verifier.nil? || code_verifier.length < 43
          session["omniauth.pkce.code_verifier"] = code_verifier

          code_challenge = generate_code_challenge(code_verifier)
          raise "Failed to generate code challenge" if code_challenge.nil? || code_challenge.empty?
          Rails.logger.debug "PKCE code_challenge: #{code_challenge}"

          # Update client options with discovered endpoints
          Rails.logger.debug "Updating client options..."
          options.client_options.site = auth_metadata[:issuer]
          options.client_options.authorize_url = auth_metadata[:authorization_endpoint]
          options.client_options.token_url = auth_metadata[:token_endpoint]

          # Set client ID based on environment
          public_url = "https://local.blueskycounter.com"
          client_id = URI.join(public_url, "/auth/atproto/client-metadata.json").to_s
          raise "Failed to construct client_id" if client_id.nil? || client_id.empty?
          options.client_id = client_id
          Rails.logger.debug "Using client_id: #{client_id}"

          # Set up authorization params
          Rails.logger.debug "Setting up authorization params..."
          options.authorize_params = {
            client_id: client_id,
            state: state,
            handle: handle,
            scope: "atproto transition:generic"
          }
          Rails.logger.debug "Authorization params: #{options.authorize_params}"

          Rails.logger.debug "Proceeding with OAuth2 flow..."
          super
        rescue StandardError => e
          Rails.logger.error "Error in request phase: #{e.class} - #{e.message}"
          Rails.logger.error e.backtrace.join("\n")
          fail!(:invalid_request, e)
        end
      end

      def callback_phase
        Rails.logger.debug "Starting callback phase"
        Rails.logger.debug "Request params: #{request.params.inspect}"

        begin
          stored_state = session.delete("omniauth.state")
          stored_issuer = session.delete("omniauth.issuer")
          stored_did = session.delete("omniauth.did")
          stored_client_id = session.delete("omniauth.client_id")
          stored_code_verifier = session.delete("omniauth.pkce.code_verifier")

          Rails.logger.debug "Retrieved session values:"
          Rails.logger.debug "  state: #{stored_state}"
          Rails.logger.debug "  issuer: #{stored_issuer}"
          Rails.logger.debug "  did: #{stored_did}"
          Rails.logger.debug "  client_id: #{stored_client_id}"
          Rails.logger.debug "  code_verifier: #{stored_code_verifier}"

          # Get the private key from credentials
          private_key_base64 = Rails.application.credentials.atproto[:private_key]
          Rails.logger.debug "Retrieved private key from credentials (first 10 chars): #{private_key_base64[0..10]}..."

          # Verify the state parameter
          unless stored_state.to_s.length > 0 && stored_state == request.params["state"]
            Rails.logger.error "State mismatch! Expected #{stored_state}, got #{request.params['state']}"
            return fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
          end

          client = ATProtoOAuthClient.new(
            stored_issuer,
            stored_client_id,
            callback_url,
            private_key_base64
          )

          access_token = client.validate_authorization_code(
            request.params["code"],
            stored_code_verifier,
            request.params["iss"],
            request.params["state"]
          )

          # ... rest of the callback phase ...
        rescue StandardError => e
          Rails.logger.error "Error in callback phase: #{e.class} - #{e.message}"
          Rails.logger.error e.backtrace.join("\n")
          fail!(:invalid_credentials, e)
        end
      end

      # Override to return our custom auth hash
      def auth_hash
        @auth_hash
      end

      private

      def resolve_atproto_handle(handle)
        Rails.logger.debug "Resolving handle: #{handle}"

        # Try DNS TXT record first
        Rails.logger.debug "Attempting DNS TXT record lookup..."
        txt_response = Faraday.get(
          "https://cloudflare-dns.com/dns-query",
          { name: "_atproto.#{handle}", type: "TXT" },
          { "Accept" => "application/dns-json" }
        )

        if txt_response.success?
          Rails.logger.debug "DNS TXT response: #{txt_response.body}"
          result = JSON.parse(txt_response.body)
          if answer = result["Answer"]&.first
            record = answer["data"]
            Rails.logger.debug "Found DNS TXT record: #{record}"
            return parse_txt_dns_record(record)
          end
        end

        # Fallback to well-known endpoint
        Rails.logger.debug "Falling back to well-known endpoint..."
        wellknown_response = Faraday.get("https://#{handle}/.well-known/atproto-did")
        if wellknown_response.success?
          Rails.logger.debug "Well-known response: #{wellknown_response.body}"
          return wellknown_response.body
        end

        raise "Failed to resolve handle through both DNS and well-known methods"
      end

      def get_pds_from_account_did(did)
        Rails.logger.debug "Getting PDS from DID: #{did}"
        raise "Empty or invalid DID" if did.nil? || did.empty?

        if did.start_with?("did:plc:")
          Rails.logger.debug "Using PLC directory resolution"
          get_pds_from_plc_did(did)
        elsif did.start_with?("did:web:")
          Rails.logger.debug "Using Web DID resolution"
          get_pds_from_web_did(did)
        else
          raise "Unknown DID format: #{did}"
        end
      end

      def get_authorization_server(pds_endpoint)
        Rails.logger.debug "Getting authorization server from PDS: #{pds_endpoint}"
        raise "Invalid PDS endpoint" if pds_endpoint.nil? || pds_endpoint.empty?

        response = Faraday.get("#{pds_endpoint}/.well-known/oauth-protected-resource")
        raise "Failed to get PDS authorization server: #{response.status}" unless response.success?

        result = JSON.parse(response.body)
        Rails.logger.debug "Authorization server response: #{result}"

        auth_server = result.dig("authorization_servers", 0)
        raise "No authorization server found in response" unless auth_server

        auth_server
      end

      def get_atproto_authorization_server_metadata(issuer)
        Rails.logger.debug "Getting authorization server metadata from: #{issuer}"
        raise "Invalid issuer" if issuer.nil? || issuer.empty?

        response = Faraday.get("#{issuer}/.well-known/oauth-authorization-server")
        raise "Failed to get authorization server metadata: #{response.status}" unless response.success?

        result = JSON.parse(response.body)
        Rails.logger.debug "Authorization server metadata: #{result}"

        raise "Invalid metadata - issuer mismatch" unless result["issuer"] == issuer

        {
          issuer:,
          pushed_authorization_request_endpoint: result["pushed_authorization_request_endpoint"],
          token_endpoint: result["token_endpoint"],
          authorization_endpoint: result["authorization_endpoint"]
        }
      end

      def parse_txt_dns_record(record)
        Rails.logger.debug "Parsing TXT record: #{record}"
        return unless record.start_with?('"') && record.end_with?('"')

        key_value = record[1..-2] # Remove surrounding quotes
        key, value = key_value.split("=")

        raise "Invalid record format - expected 'did=' prefix" unless key == "did"
        raise "Empty DID value in record" if value.nil? || value.empty?

        Rails.logger.debug "Parsed DID from TXT record: #{value}"
        value
      end

      def get_pds_from_plc_did(did)
        Rails.logger.debug "Getting PDS from PLC DID: #{did}"
        response = Faraday.get("https://plc.directory/#{did}")
        raise "Invalid DID response: #{response.status}" unless response.success?

        result = JSON.parse(response.body)
        Rails.logger.debug "PLC directory response: #{result}"

        find_pds_service_endpoint(result["service"])
      end

      def get_pds_from_web_did(did)
        Rails.logger.debug "Getting PDS from Web DID: #{did}"
        prefix = "did:web:"
        raise "Invalid Web DID format" unless did.start_with?(prefix)

        target = did[prefix.length..]
        target = target.gsub(":", "/")
        target = URI.decode_www_form_component(target)
        Rails.logger.debug "Decoded Web DID target: #{target}"

        response = Faraday.get("https://#{target}/.well-known/did.json")
        raise "Invalid DID response: #{response.status}" unless response.success?

        result = JSON.parse(response.body)
        Rails.logger.debug "Web DID document: #{result}"

        find_pds_service_endpoint(result["service"])
      end

      def find_pds_service_endpoint(services)
        Rails.logger.debug "Finding PDS service endpoint in services: #{services}"
        raise "No services found" if services.nil? || !services.is_a?(Array)

        service = Array(services).find { |s| s["id"] == "#atproto_pds" }
        raise "PDS service not found" unless service

        endpoint = service["serviceEndpoint"]
        raise "Missing serviceEndpoint in PDS service" unless endpoint

        Rails.logger.debug "Found PDS endpoint: #{endpoint}"
        endpoint
      end

      def generate_code_challenge(verifier)
        Rails.logger.debug "Generating code challenge from verifier"
        raise "Invalid verifier" if verifier.nil? || verifier.empty?

        challenge = Base64.urlsafe_encode64(
          OpenSSL::Digest::SHA256.digest(verifier),
          padding: false
        )
        Rails.logger.debug "Generated code challenge: #{challenge}"
        challenge
      end
    end
  end
end
