import requests 

'''

Docstring for training.olicyber.it.Web Challs.solutions.web 10

We need to send an OPTIONS request to the server
'''


url = "http://web-10.challs.olicyber.it/"

response = requests.options(url)

print(response.headers)