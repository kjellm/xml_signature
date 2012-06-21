[![Build Status](https://secure.travis-ci.org/kjellm/xml_signature.png?branch=master)](http://travis-ci.org/kjellm/xml_signature)

XML Signature
=============

A (partial) Ruby implementation of the XML Signature standard.

So far it can only be used to verify signed xml documents.


Install
-------

gem install xml_signature

Usage
-----

    require 'xml_signature'
    foo = REXML::Document.new(...)
    expected_certificate = "..."
    XMLSignature.new(foo).verify(expected_certificate)

Author
------

Kjell-Magne Øierud (kjellm AT oierud DOT net)
	
Bugs
----

Report bugs to http://github.com/kjellm/xml_signature/issues
	
License
-------

(The MIT License)

Copyright © 2012 Kjell-Magne Øierud

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the ‘Software’), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED ‘AS IS’, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
