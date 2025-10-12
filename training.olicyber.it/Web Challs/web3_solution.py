import requests # this line imports the requests module

url = "http://web-03.challs.olicyber.it/flag" # this line sets the url variable to the server

headers = {"X-Password": "admin"} # this line sets the headers variable to the server

response = requests.get(url, headers=headers) # this line sends a get request to the server with the headers

print(response.text) # this line prints the response from the server. We need the text of the response to get the flag otherwise we will get a 200 status code.