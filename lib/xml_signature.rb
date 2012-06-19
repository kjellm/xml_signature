# -*- coding: utf-8 -*-

require "digest/sha1"
require "openssl"
require "xmlcanonicalizer"
require 'saml'

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
    Base64.strict_encode64(algorithm_class(ds_reference).digest(signed_element_in_canonical_representation))
  end

  def c14n(node)
    with_comments = false
    exclusive     = true
    XML::Util::XmlCanonicalizer.new(with_comments, exclusive).canonicalize(node)
  end

  def signature
    Base64.decode64(xpath(@ds_signature, "//ds:SignatureValue").text)
  end

  def certificate_text
    xpath(@ds_signature, "//ds:X509Certificate").text
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

XMLSignature.new(REXML::Document.new(%q{<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7f1bf800d7fb2c6380a81df68b07ebc0422018c1b5" Version="2.0" IssueInstant="2012-06-19T12:18:37Z" Destination="http://localhost/feide/mellon/endpoint/postResponse" InResponseTo="cda19580-9c36-012f-fc85-388d120849f6"><saml:Issuer>https://idp-test.feide.no</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_ee3a7c1ef76e7bb8a96e4480342f7171a615a92cbe" Version="2.0" IssueInstant="2012-06-19T12:18:37Z"><saml:Issuer>https://idp-test.feide.no</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#_ee3a7c1ef76e7bb8a96e4480342f7171a615a92cbe"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>fGialLR9Z03EPTPegi8EFHVabJg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>umIL/zWzfaid4alX5MEaET10eqMfwvaal9p0jzimj7GVicyaGB8iHGwUDOQHd3R1TO7bpqhBJIA6BPcytGu5oFtclSWMoH2y7gygkbARQxZz1WvWnEVPAsJxrn2plnvqf8qM87RjSNAE8heoCUgB97cKCXaIBlsHPsS0WcwMUmnaqVlC6jLZXNRAwuuqR/z5Ww1XKCzl2vz3D//FDX6EhtpmikBZzu0is4YtQ4aAFuJdQYOLltR33pnMrDoG9AzuoS6pgOA9CsK6sB8cak9duQX0208CdJbWFMcK5P4mbM3brRfyedUGXQcYaOTHHdtoiuZee7CJY9drndwJ8As11w==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDkDCCAngCCQCoO7l98RIRDzANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAcTCVRyb25kaGVpbTETMBEGA1UEChMKVW5pbmV0dCBBUzEOMAwGA1UECxMFRkVJREUxGjAYBgNVBAMTEWlkcC10ZXN0LmZlaWRlLm5vMSUwIwYJKoZIhvcNAQkBFhZtb3JpYS1kcmlmdEB1bmluZXR0Lm5vMB4XDTA4MDkwNTExNTIzOFoXDTE4MDcxNTExNTIzOFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQHEwlUcm9uZGhlaW0xEzARBgNVBAoTClVuaW5ldHQgQVMxDjAMBgNVBAsTBUZFSURFMRowGAYDVQQDExFpZHAtdGVzdC5mZWlkZS5ubzElMCMGCSqGSIb3DQEJARYWbW9yaWEtZHJpZnRAdW5pbmV0dC5ubzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMzbnp+fdJ4nkgXS+EqnfHUqYOnbxMuJga+ZWJUoKQ/X2DAkZI1rPkJgi50K2mKk3me4JjN8+qEV3XLd326XALJnra8yf07l3gE2aDlR+3pMe1fhhSANVjEzY8x6kROJMq9bxreDQjimcjvdFX69FLgxjqtcwWoGcRyn2HZUYuuoWmvqFlX+985lOfLa/PJjaFbdy7XWtucMw6dDTrA+UWK4yjbenZaT/HHyn29kYQ4MKu4Mn0cYasrfrZrVSHG5L7fySVAaXEgaxToH/fVa40Z5ltHWOw2PiDOCsC1CcQFTmKDq1Gkhi1dMhm/CECJFlAR9ML7tG1Ort9q487kSNxUCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAhf/4EsLnq7EYrvW2gBjJobhweYjjjBng0gXx3yQ/ivHbApcWcbaBLyVIokiGTf7XFhxbeZaT9+vrS+yhKCrcjAfoaXbx/xVVlKLsSMZmOr1g8+4yq6v4ax6orPrsDsmRhutoAUL8AnsGIxbyG/FbjmzEYudnbR44vUnfLD2ffnIGjGLuJHZ0OPMFkPM2V2QPiJlyngrd1xvqBfnsWmWO5pDWlXa/WkxyOBiyIGcmXFJRAPtjJzxUo1CsE2PjdBIqt1bk5UDmuW8qxbDJo1kIKeqVonuAbihZzNXyAFEqV118S4IpCNF7QqBBmlgFE25RMDktiwFk2ymdM680WFBftw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID SPNameQualifier="urn:mace:feide.no:services:http.localhost.boklink.no.restrictedservice" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_792ba75671ac729f6878af5a478f2613c08dc646aa</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2012-06-19T12:23:37Z" Recipient="http://localhost/feide/mellon/endpoint/postResponse" InResponseTo="cda19580-9c36-012f-fc85-388d120849f6"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2012-06-19T12:18:07Z" NotOnOrAfter="2012-06-19T12:23:37Z"><saml:AudienceRestriction><saml:Audience>urn:mace:feide.no:services:http.localhost.boklink.no.restrictedservice</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2012-06-19T12:18:36Z" SessionNotOnOrAfter="2012-06-19T20:18:37Z" SessionIndex="_6b56557e0c70873720ffd134de0a2ab22f18b377e9"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">student</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@feide.no</saml:AttributeValue></saml:Attribute><saml:Attribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">FEIDE Test User (cn) øæåØÆÅ</saml:AttributeValue></saml:Attribute><saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">FEIDE Test User (sn) øæåØÆÅ</saml:AttributeValue></saml:Attribute><saml:Attribute Name="givenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">FEIDE Test User (givenName) øæåØÆÅ</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonEntitlement" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">urn:mace:feide.no:domain.no:testvalue</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">urn:mace:feide.no:GREP:testvalue</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Feide Test User (displayName) æøåÆØÅ</saml:AttributeValue></saml:Attribute><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">support@feide.no</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonOrgDN:norEduOrgNIN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">NO968100211</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonOrgDN:norEduOrgSchemaVersion" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">1.5</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonOrgUnitDN:norEduOrgUnitUniqueIdentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">350200</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>})).verify('MIIDkDCCAngCCQCoO7l98RIRDzANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAcTCVRyb25kaGVpbTETMBEGA1UEChMKVW5pbmV0dCBBUzEOMAwGA1UECxMFRkVJREUxGjAYBgNVBAMTEWlkcC10ZXN0LmZlaWRlLm5vMSUwIwYJKoZIhvcNAQkBFhZtb3JpYS1kcmlmdEB1bmluZXR0Lm5vMB4XDTA4MDkwNTExNTIzOFoXDTE4MDcxNTExNTIzOFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQHEwlUcm9uZGhlaW0xEzARBgNVBAoTClVuaW5ldHQgQVMxDjAMBgNVBAsTBUZFSURFMRowGAYDVQQDExFpZHAtdGVzdC5mZWlkZS5ubzElMCMGCSqGSIb3DQEJARYWbW9yaWEtZHJpZnRAdW5pbmV0dC5ubzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMzbnp+fdJ4nkgXS+EqnfHUqYOnbxMuJga+ZWJUoKQ/X2DAkZI1rPkJgi50K2mKk3me4JjN8+qEV3XLd326XALJnra8yf07l3gE2aDlR+3pMe1fhhSANVjEzY8x6kROJMq9bxreDQjimcjvdFX69FLgxjqtcwWoGcRyn2HZUYuuoWmvqFlX+985lOfLa/PJjaFbdy7XWtucMw6dDTrA+UWK4yjbenZaT/HHyn29kYQ4MKu4Mn0cYasrfrZrVSHG5L7fySVAaXEgaxToH/fVa40Z5ltHWOw2PiDOCsC1CcQFTmKDq1Gkhi1dMhm/CECJFlAR9ML7tG1Ort9q487kSNxUCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAhf/4EsLnq7EYrvW2gBjJobhweYjjjBng0gXx3yQ/ivHbApcWcbaBLyVIokiGTf7XFhxbeZaT9+vrS+yhKCrcjAfoaXbx/xVVlKLsSMZmOr1g8+4yq6v4ax6orPrsDsmRhutoAUL8AnsGIxbyG/FbjmzEYudnbR44vUnfLD2ffnIGjGLuJHZ0OPMFkPM2V2QPiJlyngrd1xvqBfnsWmWO5pDWlXa/WkxyOBiyIGcmXFJRAPtjJzxUo1CsE2PjdBIqt1bk5UDmuW8qxbDJo1kIKeqVonuAbihZzNXyAFEqV118S4IpCNF7QqBBmlgFE25RMDktiwFk2ymdM680WFBftw==')