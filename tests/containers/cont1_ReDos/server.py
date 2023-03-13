
import re
from flask import Flask,jsonify
from flask_cors import CORS
import random

ATTACK_STRING_LENGTH = 22

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
def do_evil():
    evil_rex = r"^(a|a?)+b$"
    length = random.randint(10, ATTACK_STRING_LENGTH)
    string = ''.join(random.choices(['a'], k=length))
    print(string)
    print(re.search(evil_rex, string))
    data = {'message': 'Hi'}
    response = jsonify(data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response
 

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8081)