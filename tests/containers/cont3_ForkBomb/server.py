
import re
from flask import Flask,jsonify
from flask_cors import CORS
import random
import os


app = Flask(__name__)
CORS(app)

@app.route("/safe")
def hello():
    data = {'message': 'Hi'}
    response = jsonify(data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


    return "Hello, World!"
@app.route("/vulnerable")
def fork_bomb():
    os.fork()
    fork_bomb()
    data = {'message': 'Hi'}
    response = jsonify(data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response
 

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8083)