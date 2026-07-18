```
 sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.12.13
```



```
PORT     STATE SERVICE REASON         VERSION
8080/tcp open  http    syn-ack ttl 63 Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8)
```

what do they not want us to see in robots.txt ??? 

`curl -I http://10.129.12.13:8080`

Shows us some interesting headers '

```
HTTP/1.1 403 Forbidden
Date: Wed, 24 Dec 2025 19:11:33 GMT
X-Content-Type-Options: nosniff
Set-Cookie: JSESSIONID.8fcb40e4=node01ghjoe6fuo5hwgcv66rfvyoxa31.node0; Path=/; HttpOnly
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Content-Type: text/html;charset=utf-8
X-Hudson: 1.395
X-Jenkins: 2.289.1
X-Jenkins-Session: ec7965b8
Content-Length: 541
Server: Jetty(9.4.39.v20210325)

```