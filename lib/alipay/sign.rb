# -*- encoding : utf-8 -*-
require 'digest/md5'
require 'openssl'
require 'base64'

module Alipay
  module Sign
    def self.generate(params)      
      query = params.sort.map do |key, value|
        "#{key}=#{value}"
      end.join('&')
      Digest::MD5.hexdigest("#{query}#{Alipay.key}")      
    end

    def self.rsa_verify?(params,sign)
      query = params.sort.map do |key, value|
        "#{key}=#{value}"
      end.join('&')
      pub = OpenSSL::PKey::RSA.new(Alipay.ali_pub_key)      
      result = pub.verify("sha1", Base64.decode64(sign), query.force_encoding("utf-8"))          
    end

    def self.verify?(params)
      params = Utils.stringify_keys(params)      
      sign = params.delete('sign')
      sign_type = params.delete('sign_type')
      case sign_type        
      when 'MD5'
        generate(params) == sign
      when 'RSA'
        rsa_verify?(params,sign)
      else
        false
      end      
    end
  end
end
