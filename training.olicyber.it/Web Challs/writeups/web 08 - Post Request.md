So far, we've focused exclusively on retrieving resources from the server, but HTTP also provides tools for the reverse operation. These are the POST and PUT verbs, which allow you to send a resource to the server, specifying a destination address. The difference between the two methods is subtle, but we'll focus solely on POST, which is by far the most widely used of the two, as it's associated, for example, with submitting the content of forms included on many websites.

In principle, the representation of the submitted resource in the body of a POST request can use any format, but for historical reasons, when using the browser's built-in submission mechanism to submit form content, it is typically encoded using a legacy format specific to web forms, known in the MIME classification as application/x-www-form-urlencoded. For this reason, many servers that receive data from users via POST requests preferentially accept this format, even when the data source is not a web form.

The goal of this challenge is to send a POST request to the resource, http://web-08.challs.olicyber.it/loginproviding application/x-www-form-urlencodedthe value pair "username": "admin"and in the format "password": "admin", similar to a hypothetical operation to submit a login form on a website. The flag will be returned in the response text.

The format application/x-www-form-urlencodedis relatively complicated to reproduce, but like other parts of the HTTP protocol we've seen so far, it essentially represents a sequence of key-value pairs, and the library requestsprovides a mechanism to automatically generate it from a Python dictionary. It's recommended to use the library's postdata function parameter .requets


In this challenge we used the requests module in python to send data to the webserver

```
data = { "username": "admin", "password": "admin" }

response = requests.post(url, data=data)
```

data stores the key value pairs and the post library sends the request in the correct format