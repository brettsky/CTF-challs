import requests
import json

session = requests.Session()
csrf = None

def get_csrf_token():
    url = "http://web-11.challs.olicyber.it/login"
    json = {
        "username": "admin",
        "password": "admin"
    }   
    response = session.post(url, json=json)
    token = response.json().get('csrf')
    print(f"login csrf {token}")
    return token

def get_flag_piece(index):
    global csrf
    url = f"http://web-11.challs.olicyber.it/flag_piece?index={index}&csrf={csrf}"
    data = session.get(url).json()
    csrf = data.get('csrf')
    print(f"[next csrf] {csrf}")
    return data.get('flag_piece')

csrf = get_csrf_token()
for i in range(4):
    print(get_flag_piece(i), end="")