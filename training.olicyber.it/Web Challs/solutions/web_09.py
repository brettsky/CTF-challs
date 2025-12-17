
import requests

url = "http://web-09.challs.olicyber.it/login"

data = {'username':'admin', 'password':'admin'}


request = requests.post(url, json=data)

print(request.text)
