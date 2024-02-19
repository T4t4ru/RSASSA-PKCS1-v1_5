import os

from OpenSSL import crypto
from OpenSSL.crypto import verify
from lxml import etree
from signxml import XMLSigner, methods, XMLVerifier

from helpers import decode_utf8_2d_array


def firmar(
    xml, private_key, public_key, digital_sign=False, output_directory=None
) -> str:
    # Xml Loading
    doc = etree.fromstring(xml)

    # Create sign
    signer = XMLSigner(method=methods.enveloped)
    signed_doc = signer.sign(doc, key=private_key, cert=public_key)

    # Don't forget to include certificate in it
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, public_key)

    # Loading meta
    result = add_meta(signed_doc, certificate)

    if digital_sign is False:
        result = result.replace("ds:", "")

    if output_directory:
        output_path = os.path.join(output_directory, "signed_xml.xml")
    else:
        output_path = "signed_xml.xml"

    with open(output_path, "wb") as output_file:
        output_file.write(result.encode("utf-8"))

    return result


def firmar_verify(xml, private_key, public_key, digital_sign=True):
    with open("signed_xml.xml", "rb") as file:
        new_xml = file.read()

    # Загрузка XML
    doc = etree.fromstring(new_xml)

    # Проверка подписи
    verified = XMLVerifier().verify(doc, x509_cert=public_key)

    if verified:
        print("Sign is correct")
    else:
        print("Sign is incorrect")


def issuer_transform(issuer_components: list):
    issuer_components.reverse()
    decoded = decode_utf8_2d_array(issuer_components)

    result = ",".join(list(map(lambda x: f"{x[0]}={x[1]}", decoded)))
    return result


def add_meta(root, certificate):
    issuer_serial = certificate.get_serial_number()
    subject_name = certificate.get_subject().CN
    issuer_name = issuer_transform(certificate.get_issuer().get_components())

    # Find and create an element X509Data inside KeyInfo
    nsmap = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
    key_info = root.find(".//ds:KeyInfo", namespaces=nsmap)
    if key_info is None:
        key_info = etree.SubElement(root, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")

    x509_data = key_info.find(".//ds:X509Data", namespaces=nsmap)
    if x509_data is None:
        x509_data = etree.SubElement(
            key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data"
        )

    # Add X509SubjectName
    x509_subject_name = etree.SubElement(
        x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509SubjectName"
    )
    x509_subject_name.text = subject_name

    # Add X509IssuerSerial
    x509_issuer_serial = etree.SubElement(
        x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerSerial"
    )

    # Add X509IssuerName
    x509_issuer_name = etree.SubElement(
        x509_issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerName"
    )
    x509_issuer_name.text = issuer_name

    # Add X509SerialNumber
    x509_serial_number = etree.SubElement(
        x509_issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber"
    )
    x509_serial_number.text = str(issuer_serial)

    return etree.tostring(root, pretty_print=True, xml_declaration=True).decode()
