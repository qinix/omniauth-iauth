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
      option :authorize_params, {}
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
        iauth = ::IAuth.new options.app_id, options.app_secret
        if operate == 'login'
          c = iauth.login verifier, state
        elsif operate == 'auth'
          c = iauth.auth verifier, state
        else
          fail!(:invalid_request, CallbackError.new(:invalid_request))
        end
        options.uid = c['uid']
        options.access_token = c['access_token']
        options.access_secret = c['access_secret']
        super
      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      rescue ::MultiJson::DecodeError => e
        fail!(:invalid_response, e)
      rescue ::OmniAuth::NoSessionError => e
        fail!(:session_expired, e)
      end

      uid do
        options.uid
      end

      # info do
      # end

      credentials do
        c = { 'access_token' => options.access_token }
        c['access_secret'] = options.access_secret unless options.access_secret.nil?
        c
      end

      # extra do
      # end

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
