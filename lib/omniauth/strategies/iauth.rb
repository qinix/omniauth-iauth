require 'securerandom'
require 'omniauth'
require 'iauth'

module OmniAuth
  module Strategies
    class IAuth
      include OmniAuth::Strategy

      args [:app_id, :app_secret]

      option :app_id, nil
      option :app_secret, nil
      option :uid, nil
      option :access_token, nil
      option :access_secret, nil

      attr_reader :access_token

      def request_phase
        state = options.authorize_params[:state] = SecureRandom.hex(8)
        session['omniauth.state'] = state
        redirect "http://i.buaa.edu.cn/plugin/iauth/login.php?appid=#{options.app_id}&state=#{state}"
      end

      def callback_phase
        operate = request.params['operate']
        verifier = request.params['verifier']
        state = request.params['state']
        fail!(:invalid_request, CallbackError.new(:invalid_request)) unless state == session['omniauth.state']
        iauth = IAuth.new options.app_id, options.app_secret
        if operate == 'login'
          self.access = iauth.login verifier, state
        elsif operate == 'auth'
          self.access = iauth.auth verifier, state
        else
          fail!(:invalid_request, CallbackError.new(:invalid_request))
        end
        super
      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      rescue ::OAuth::Unauthorized => e
        fail!(:invalid_credentials, e)
      rescue ::MultiJson::DecodeError => e
        fail!(:invalid_response, e)
      rescue ::OmniAuth::NoSessionError => e
        fail!(:session_expired, e)
      end

      uid do
        access['uid']
      end

      info do

      end

      credentials do
        access
      end

      extra do
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'iauth', 'IAuth'
