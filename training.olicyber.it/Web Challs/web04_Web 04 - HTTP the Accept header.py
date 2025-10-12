import requests # this line imports the requests module

url = "http://web-04.challs.olicyber.it/users" # this line sets the url variable to the server

headers = {"Accept": "application/xml"} # this line sets the headers variable to the server. In this case we set the Accept header to application/xml

response = requests.get(url, headers=headers) # this line sends a get request to the server with the headers

print(response.text) # this line prints the response from the server. 


# we see that we recieve an XML response instead of a JSON response. 
# and we see a user comment in the XML response containing the flag.
#  <user comment="flag{54m3_7hing_diff3r3n7_7hing}">