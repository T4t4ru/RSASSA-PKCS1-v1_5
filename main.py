from flask import Flask, Response, request
from lxml import etree
from signxml import XMLSigner, methods, XMLVerifier
from OpenSSL import crypto

from docs import xml_output_to_match, xml_to_sign, private_key, public_key_cert
from sign import firmar, firmar_verify

app = Flask(__name__)


@app.route("/xml-to-sign")
def raw_xml():
    return Response(xml_to_sign, mimetype="text/xml")


@app.route("/xml-output-match")
def original_xml():
    return Response(xml_output_to_match, mimetype="text/xml")


def is_it_true(value):
    return value.lower() == "true"


@app.route("/signed-xml")
def signed_xml():
    digital_sign = request.args.get("digital_sign", default=False, type=is_it_true)

    signed_doc = firmar(
        xml_to_sign, private_key, public_key_cert, digital_sign=digital_sign
    )
    return Response(signed_doc, mimetype="text/xml")


@app.route("/verify-signed-xml")
def verify_signed_xml():
    verify = firmar_verify(xml_to_sign, private_key, public_key_cert)
    return Response(verify)


app.run(host="localhost", port=8000)
