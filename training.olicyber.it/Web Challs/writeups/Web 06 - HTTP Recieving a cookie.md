Cookies are not a redundant mechanism compared to the other types of parameters observed so far. Unlike them, the server can request the installation of cookies provided by it in the client's memory. These cookies are associated with the site that generated them and may contain an expiration date.

Web browsers manage this storage automatically, and saved cookies are automatically sent in subsequent requests to the same site and deleted when the specified time is reached. This way, they can be used to identify a session with a specific client, or a series of consecutive requests made from the same device, even when multiple devices are connected to the Internet via the same subnet and therefore share an IP address.

The goal of this challenge is to perform a GET request to the resource http://web-06.challs.olicyber.it/tokenwhich will attempt to install a session cookie, once obtained it will be possible to log in http://web-06.challs.olicyber.it/flagto get the flag.

getThe library function requestsused so far adopts a stateless model , meaning it doesn't use any of the information previously received from the server when composing subsequent requests. To complete this challenge, it's recommended to instantiate a Session class object and execute requests using its method get, which differs from the normal function getprecisely because it saves this information within the object, partially emulating the behavior of a browser.


In this challenge we made use of the session class within the requests module 

```
s = requests.Session()
```

In this line we initialize our session this lets us see our current cookies with this print statement  

```
print(s.cookies)
```

We see the values RequestsCookieJar Cookie token=e818ef49-8331-4677-8404-fd3c52bed03f for web-06.challs.olicyber.it in our console

we send the token value as a cookie to  http://web-06.challs.olicyber.it/flag


```
r = s.get("http://web-06.challs.olicyber.it/flag",cookies = {'token': '0981b440-8f7e-4b63-aed9-e22ae83edb26'})

print(r.text) # this line prints the response from the server. We need the text of the response to get the flag otherwise we will get a 200 status code.

#flag{s3ss10n_c00k135}

```

We get the flag and complete the chall