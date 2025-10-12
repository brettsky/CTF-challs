Among the information exchanged between client and server via HTTP headers are small pieces of information called cookies . Unlike non-standard headers, cookies are specifically designed by the HTTP standard to contain arbitrary data useful for the operation of websites and web services and are commonly used as part of authentication mechanisms additional to those offered by the standard.

Similar to challenge number 3, the goal is to obtain the resource http://web-05.challs.olicyber.it/flagby providing the string adminin a cookie named password. It is recommended to use the cookies parameter of the function getused so far.


This challenge is teaching us about http cookies and how to send one manually 

```
cookies = {"password": "admin"}

response = requests.get(url, cookies=cookies)
```

we learned about cookies and how to send one manually. In this request we sent a cookie with the value of admin in for our password