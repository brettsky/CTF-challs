

This lab contains a stored cross-site scripting vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.


This is stored XSS because it is not immediatley ran like in reflected XSS vulns 

We use the same payload to exploit the vulnerability '<script>alert('hacked')</script>'

This payload proves that we can store a javascript payload


```
Stored cross-site scripting (also known as second-order or persistent XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.
```


The javascript is stored in the comment

```
Any user who visits the blog post will now receive the following within the application's response:

`<p><script>/* Bad stuff here... */</script></p>`

The script supplied by the attacker will then execute in the victim user's browser, in the context of their session with the application.
```
This could easily be an http request to a http server with the users session cookies 


# To find

Figure out entry and exit points of data. Easiest example is a comment section but this could be HTTP headers, the file path. or URL parameters/ message body