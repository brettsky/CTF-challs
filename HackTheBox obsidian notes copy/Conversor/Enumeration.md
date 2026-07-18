`sudo nmap -vvv -Pn -sCV --reason -p0-65535  -T4 10.129.42.207`

```
PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9JqBn+xSQHg4I+jiEo+FiiRUhIRrVFyvZWz1pynUb/txOEximgV3lqjMSYxeV/9hieOFZewt/ACQbPhbR/oaE=
|   256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIR1sFcTPihpLp0OemLScFRf8nSrybmPGzOs83oKikw+
80/tcp    open     http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
1045/tcp  filtered fpitp   no-response
1375/tcp  filtered bytex   no-response
6986/tcp  filtered unknown no-response
9587/tcp  filtered unknown no-response
41380/tcp filtered unknown no-response
48397/tcp filtered unknown no-response
50905/tcp filtered unknown no-response
60604/tcp filtered unknown no-response
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel=
```

We add Conversor.htb to our /etc/hosts file to access the site via web browser. 

We are presented with a login page. We try some common usernames and passwords before registering an account 
![[Pasted image 20260118135432.png]]

We are Conversor. Have you ever performed large scans with Nmap and wished for a more attractive display? We have the solution! All you need to do is upload your XML file along with the XSLT sheet to transform it into a more aesthetic format. If you prefer, you can also download the template we have developed here: [Download Template](http://conversor.htb/static/nmap.xslt)
`oX <filename> to output a file to XML in Nmap`

An XSLT file is an XML-based file that contains instructions for transforming an XML document into another format. stands for eXtensible Stylesheet Language Transformations.

We also find the source code in the about section..How convenient 
`tar -xzf <file name>` to unzip the source code 

We open the code in VScode to take a better look. 

We see this is a Flask Web app using Sqlite3

`DB_PATH = '/var/www/conversor.htb/instance/users.db'`

When seeing a flask app. My first thought is any potential SSTI - Server Side Template injection but we also have the file upload capabilities - Googling we find  https://ine.com/blog/xslt-injections-for-dummies XSLT injection for dumbasses like me. We find the XML version of the template to be 1.0 `<?xml version="1.0" encoding="UTF-8"?>`
![[Pasted image 20260118150629.png]]

This will deal with Libxslt

Uploading a file brings us to
`http://conversor.htb/view/f428515e-b8fd-48e5-a04a-af41ff1caff8`

So we are brought to the view page. This is the flask route that handles rhis 

```
@app.route('/view/<file_id>')

def view_file(file_id):

if 'user_id' not in session:

return redirect(url_for('login'))

conn = get_db()

cur = conn.cursor()

cur.execute("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, session['user_id']))

file = cur.fetchone()

conn.close()

if file:

return send_from_directory(UPLOAD_FOLDER, file['filename'])

return "File not found"
```


# Shell as WWW-Data
---

```
www-data@conversor:/$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
syslog:x:106:113::/home/syslog:/usr/sbin/nologin
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
tss:x:109:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fismathack:x:1000:1000:fismathack:/home/fismathack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```