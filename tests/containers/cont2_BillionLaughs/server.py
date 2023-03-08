from flask import Flask, request,Response
import defusedxml.ElementTree as ET
import xml.dom.minidom


app = Flask(__name__)

@app.route('/vulnerable')
def vulnerable():
    doc = xml.dom.minidom.parse("xml.xml");
    return xml_, {'Content-Type': 'application/xml'}



@app.route('/fixed')
def fixed():
    xml = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE lolz [' + ''.join(['<!ENTITY lol{} "lol">'.format(i) for i in range(100000)]) + ']><lolz>&lol0;</lolz>'
    try:
        ET.fromstring(xml)
        return Response('OK', status=200)
    except ET.ParseError as e:
        return Response(str(e), status=400)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8082)