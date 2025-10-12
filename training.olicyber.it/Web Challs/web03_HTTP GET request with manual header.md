When an HTTP request is sent, in addition to the verb, the path to the desired resource, and any associated parameters, some additional information is communicated to the server in fields called headers (derived from the fact that they are sent in the first part of the HTTP message). Similarly, the server will also attach headers to the response in addition to the requested content. These headers differ from the GET request parameters because they are not used to specify the requested resource, but contain information about the client (called user-agent ), the server, and the communication channel, metadata associated with the resources, and any debugging information.

These headers are generally inserted automatically by the client and server libraries and belong to a standard set defined as part of the protocol itself; however, additional headers can be specified to meet the needs of particular applications. These non-standard headers typically have names starting with , X-and when sent to a system that cannot recognize them, they are usually ignored.

In this challenge, a non-standard header was used to provide a homemade authentication mechanism. The goal is to retrieve the text of the resource at address http://web-03.challs.olicyber.it/flag, but the server will only respond to requests that contain the header X-Passwordcontaining the correct password, admin.

It is recommended to use the headers keyword of the function getused in previous challenges.


In this challenge we have to send a custom header of  X-Password containing the password for admin 

```
headers = {"X-Password": "admin"} 

and 

response = requests.get(url, headers=headers)
```

Are the main learning from this challenge. We learned about the headers keyword in the requests module and how to send a custom header. Without sending this header we recieve an unauthorized error, 

As the name implies we sent an http request with a manually set header. This proves that these headers cannot be trusted for websecurity as they can be modified by the user.