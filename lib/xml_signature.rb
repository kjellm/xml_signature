# -*- coding: utf-8 -*-

require "digest/sha1"
require "openssl"
require "xmlcanonicalizer"

class XMLSignature

  # xml - A REXML document
  def initialize(xml)
    @xml = xml.dup
    @ds_signature = xpath(@xml, '//ds:Signature')
    @ds_signature.remove
  end

  def verify(expected_certificate)
    raise "Certificate mismatch" if expected_certificate != given_certificate

    REXML::XPath.each(@ds_signature, "//ds:Reference") do |ref|
      raise "Digest mismatch!" if computed_digest_value(ref) != given_digest_value(ref)
    end

    raise "Signature mismatch" \
      unless certificate.public_key.verify(signature_algorithm_class.new,
                                           signature,
                                           c14n(xpath(@ds_signature, "//ds:SignedInfo")))
    true
  end

  private

  def given_digest_value(ds_reference)
    xpath(ds_reference, "//ds:DigestValue").text
  end

  def computed_digest_value(ds_reference)
    signed_element_in_canonical_representation = c14n(signed_element(ds_reference))
    Base64.encode64(algorithm_class(ds_reference).digest(signed_element_in_canonical_representation)).chop
  end

  def c14n(node)
    with_comments = false
    exclusive     = true
    XML::Util::XmlCanonicalizer.new(with_comments, exclusive).canonicalize(node)
  end

  def signature
    Base64.decode64(xpath(@ds_signature, "//ds:SignatureValue").text.strip)
  end

  def certificate_text
    xpath(@ds_signature, "//ds:X509Certificate").text.strip
  end
  
  alias :given_certificate :certificate_text

  def certificate
    OpenSSL::X509::Certificate.new(Base64.decode64(certificate_text))
  end

  def signed_element(ds_reference)
    id = reference_uri_to_id(ds_reference.attributes['URI'])
    xpath(@xml, "//[@ID='#{id}']")
  end

  def reference_uri_to_id(uri)
    uri[1..-1] # remove the '#' prefix
  end
    
  def algorithm_class(ds_reference)
    # Legal algorithm URIs: http://www.w3.org/TR/xmlsec-algorithms/#digest-method-uris
    digest_method = xpath(ds_reference, "//ds:DigestMethod").attributes['Algorithm']
    case digest_method
    when 'http://www.w3.org/2000/09/xmldsig#sha1'
      OpenSSL::Digest::SHA1
    else
      raise "Do not support digest method: #{digest_method}"
    end
  end

  def signature_algorithm_class
    # Legal algorithm URIs: http://www.w3.org/TR/xmlsec-algorithms/#signature-method-uris
    signature_method = xpath(@ds_signature, "//ds:SignatureMethod").attributes['Algorithm']
    case signature_method
    when 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
      OpenSSL::Digest::SHA1
    else
      raise "Do not support signature method: #{digest_method}"
    end
  end

  def xpath(node, path)
    REXML::XPath.first(node, path, {'ds' => 'http://www.w3.org/2000/09/xmldsig#'})
  end

end
