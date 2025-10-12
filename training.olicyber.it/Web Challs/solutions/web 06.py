



import requests # this line imports the requests module

s = requests.Session() # this line instantiates a Session class object

s.get("http://web-06.challs.olicyber.it/token") # this line sends a get request to the server

print(s.cookies) # <Cookie token=0981b440-8f7e-4b63-aed9-e22ae83edb26 for web-06.challs.olicyber.it/>]>

# we can use this token to send a get request to the server and get the flag

r = s.get("http://web-06.challs.olicyber.it/flag",cookies = {'token': '0981b440-8f7e-4b63-aed9-e22ae83edb26'})

print(r.text) # this line prints the response from the server. We need the text of the response to get the flag otherwise we will get a 200 status code.

#flag{s3ss10n_c00k135}
