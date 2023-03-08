from flask import Flask, request,Response,jsonify
import defusedxml.ElementTree as ET
import xml.dom.minidom
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/vulnerable')
def vulnerable():
    doc = xml.dom.minidom.parse("xml.xml");
    data = {'message': 'Hi'}
    response = jsonify(data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response
    



@app.route('/safe')
def fixed():
    data = {'message': 'Hi'}
    response = jsonify(data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8082)