import requests # this line imports the requests module

url = "http://web-02.challs.olicyber.it/server-records" # this line sets the url variable to the server

params = {"id": "flag"} # this line sets the params variable to the server#
# params is now a variable type of a dictionary

response = requests.get(url, params=params) # this line sends a get request to the server with the params 

print(response.text) # this line prints the response from the server. We need the text of the response to get the flag otherwise we will get a 200 status code.
