from flask import Flask, request
import flask
from flask.globals import session
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.datastructures import Accept
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import xmltodict
import random
import base64
import json
import ipaddress

app = Flask(__name__)
auth = HTTPBasicAuth()
bearer = HTTPTokenAuth(scheme='Bearer')

json_data = {
    "response": {
        "status": "success",
        "name": "http mock server",
        "date": date.today(),
        "time": datetime.now().strftime("%H:%M:%S"),
        "details": {
            "id": "12345",
            "name": "dummy data",
            "description": "ubot testing for generic http servers"
        },
        "data": []
    }
}

id = 3896

xml_data = xmltodict.unparse(json_data, pretty=True)

users = {
    'admin': generate_password_hash('admin')
}

tokens = dict()
sessions = dict()
allocated = dict()

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

@bearer.verify_token
def verify_token(token):
    if token in tokens:
        return tokens[token]

@app.route('/', methods=['GET'])
def get_endpoints():
    ep_dict = {
        'endpoints': {
            'GET': '/api/v1/get_data',
            'POST': '/api/v1/post_data',
            'PUT': '/api/v1/modify_data',
            'PATCH': '/api/v1/modify_data',
            'DELETE': '/api/v1/remove_data',
            'HEAD': '/api/v1/head',
            'RESET': '/api/v1/reset_data',
            'TEST TOKEN': '/token-auth',
            'GET TOKEN (header)': '/api/v1/get-token',
            'GET TOKEN': '/api/v2/get_token',
            'GET SESSION': '/api/v2/get_session',
            'ALLOCATE': '/api/v2/allocate',
            'DEALLOVATE': '/api/v2/deallocate'
        }
    }
    if request.headers.get('accept') == 'application/xml':
        return xmltodict.unparse(ep_dict, pretty=True), 200
    else:
        return ep_dict, 200


def print_globals(task):
    print("-------------------", task, "--------------------")
    print("tokens: ", tokens)
    print("sessions: ", sessions)
    print("allocated: ", allocated)
    print("-------------------------------------------------")

@app.route('/api/v2/get_token', methods=['POST'])
def get_access_token():
    global tokens
    data = json.loads(request.get_data().decode())
    username = data.get('user')
    num = random.randint(10000, 99999)
    tm = datetime.now()
    token_string = f'{tm}{username}{num}'
    token = base64.b64encode(token_string.encode()).decode()
    tokens[token] = username
    return f'"token": "{token}"', 200


@app.route('/api/v2/get_session', methods=['POST'])
def get_session():
    global sessions
    data = json.loads(request.get_data().decode())
    token = data.get('token')
    if token not in tokens:
        return "Invalid token", 400
    session_id = random.randint(20124, 99999)
    sessions[session_id] = token
    return f'"session-id": "{session_id}"', 200


@app.route('/api/v2/allocate', methods=['POST'])
def allocate():
    data = json.loads(request.get_data().decode())
    token = data.get('token')
    session = data.get('session')
    if int(session) not in sessions:
        return "Invalid session id", 400
    if sessions.get(int(session)) != token:
        return "Invalid token", 400
    subnet = data.get('subnet')
    network = ipaddress.ip_network(subnet)
    for add in network.hosts():
        if add not in allocated.values():
            allocated[int(session)] = add
            return f'"ip-address": "{add}"', 200
    return 'no address available', 400


@app.route('/api/v2/deallocate', methods=['POST'])
def deallocate():
    data = json.loads(request.get_data().decode())
    token = data.get('token')
    session = data.get('session')
    if int(session) not in sessions:
        return "Invalid session id", 400
    if sessions.get(int(session)) != token:
        return "Invalid token", 400
    if int(session) in allocated:
        del allocated[int(session)]
    return "Deallocated", 200


@app.route('/api/v1/get_data', methods=['GET'])
def get_data():
    try:
        accept = request.headers.get('accept')
        if accept == 'application/xml':
            xml_data = xmltodict.unparse(json_data, pretty=True)
            return xml_data, 200
        else:
            return json_data, 200
    except Exception as e:
        return f"{e}", 500

@app.route('/api/v1/get_data/<id>', methods=['GET'])
def get_data_by_id(id):
    try:
        print(id)
        final_data = {
            "msg": "no data found"
        }
        data = json_data.get('response').get('data')
        for d in data:
            print(d.get('id'))
            if d.get('id') and str(d.get('id')) == id:
                final_data = d
        accept = request.headers.get('accept')
        if accept == 'application/xml':
            return xmltodict.unparse(final_data, pretty=True), 200
        else:
            return final_data, 200
    except Exception as e:
        return f"{e}", 500


def update(success_code):
    global id
    try:
        data = None
        content_type = request.headers.get('Content-Type')
        print(content_type)
        if content_type == 'application/json':
            data = request.get_json()
            data['id'] = id
            id = id+1
            input_type = 'json'
        elif content_type == 'application/xml':
            data = request.get_data().decode()
            try:
                data_dict = xmltodict.parse(data)
                data = xmltodict.unparse(data_dict, pretty=True)
                input_type = 'xml'
            except Exception as e:
                return {
                    'status': 'failure',
                    'msg': f'invalid xml: {e}'
                }, 400
        elif content_type == 'application/x-www-form-urlencoded':
            print('step-1')
            data = request.form
            print(data)
            input_type = 'form data'
        elif 'multipart/form-data' in content_type:
            data = request.form
            files = request.files
            print(files)
            input_type = 'mulitpart form data'
        else:
            data = request.get_data().decode()
            input_type = 'raw data'
        if data is not None and data != "":
            try:
                json_data['response']['data'].append(data)
            except Exception as e:
                pass
            finally:
                return {
                    'status': 'success',
                    'msg': 'valid input',
                    'input-type': input_type,
                    'input': data
                }, success_code
        else:
            return {
                'status': 'success',
                'msg': 'input is None'
            }, success_code
    except Exception as e:
        print(e)
        return {
            'status': 'failure',
            'msg': f'{e}'
        }, 500

@app.route('/api/v1/create_data', methods=['POST'])
def post_data():
    return update(201)


@app.route('/api/v1/modify_data/<id>', methods=['PUT', 'PATCH'])
def put_data(id):
    return update(202)

@app.route('/api/v1/reset_data', methods=['POST'])
def reset():
    json_data['response']['data'] = []
    return "", 204


@app.route('/api/v1/remove_data', methods=['DELETE'])
def delete_data():
    try:
        data = ""
        if len(request.args.to_dict().keys()) != 0:
            for key in request.args.keys():
                data = f'{data}{key}={request.args.get(key)} '
            return {
                'status': 'success',
                'msg': f'Data deleted for {data}'
            }, 202
        elif request.get_data().decode() != "":
            data = request.get_data().decode()
            if request.headers['content-type'] == 'application/json':
                data = json.loads(data)
            return {
                'status': 'success',
                'msg': f'Data deleted for {data}'
            }, 202
        else:
            return "", 204
    except Exception as e:
        return {
            'status': 'failure',
            'msg': f'{e}'
        }, 500

@app.route('/api/v1/head', methods=['HEAD'])
def head():
    return {"content": "some content"}, 202

@app.route('/api/v1/get-token', methods=['GET'])
@auth.login_required
def get_token():
    global tokens
    username = auth.username()
    token = 'MjAyMS0wOS0yOCAwNTozNTo1Mi44MDg1NTNhZG1pbjQzNzM0'
    tokens[token] = username
    response = flask.Response()
    print(token)
    response.headers['Access-token'] = token
    return response

@app.route('/token-auth', methods=['GET'])
@bearer.login_required
def test_token_auth():
    return f"welcome {bearer.current_user()}", 200



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)