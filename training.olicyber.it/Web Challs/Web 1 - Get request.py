import requests # this line imports the requests module

url = "http://web-01.challs.olicyber.it/" # this line sets the url variable to the server

response = requests.get(url) # this line sends a get request to the server

print(response.text) # this line prints the response from the server. We need the text of the response to get the flag otherwise we will get a 200 status code.