#!/home/jondot/.rbenv/shims/ruby

require "openssl"
require "digest/sha2"
require 'base64'



def public_key_to_id(public_key)

    #public_key = public_key[0..-2] #cuts the '\n' at the end
    p public_key

#    # Key algorithm, found in <http://github.com/Constellation/crxmake>.
#    algo = %w(30 81 9F 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 81 8D 00).map{ |s| s.hex }.pack("C*")


#    # Calculate public key, get hex hash of first 128 bits / 32 characters
#    hash = Digest::SHA256.hexdigest(algo + OpenSSL::PKey::RSA.new(pkey).public_key.to_der)[0...32]


    public_key = Base64.decode64(public_key)
    p public_key
    hash = Digest::SHA256.hexdigest(public_key)[0...32]



    # Shift hex from 0-9a-f to a-p
    hash.unpack("C*").map{ |c| c < 97 ? c + 49 : c + 10 }.pack("C*")
end



puts public_key_to_id(File.read(ARGV[0]))

