
Password and hash cracking 

## Dictionary attacks

Use a predefined list of potential passwords - containing common passwords

## Mask attacks 

Similar to brute force they use a specific format instead - aiming to reduce time 

```
pdfcrack -f flag.pdf -w /usr/share/wordlists/rockyou.txt 
PDF version 1.7
Security Handler: Standard
V: 2
R: 3
P: -1060
Length: 128
Encrypted Metadata: True
FileID: 3792b9a3671ef54bbfef57c6fe61ce5d
U: c46529c06b0ee2bab7338e9448d37c3200000000000000000000000000000000
O: 95d0ad7c11b1e7b3804b18a082dda96b4670584d0044ded849950243a8a367ff
found user-password: 'naughtylist'

```


Example: using `john` 

- Create a hash that John can understand: `zip2john flag.zip > ziphash.txt`

Terminal

```shell-session
ubuntu@tryhackme:~/Desktop$ zip2john flag.zip > ziphash.txt  
```

```
john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size [KiB]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
winter4ever      (flag.zip/flag.txt)     
1g 0:00:00:00 DONE (2025-12-10 02:53) 2.128g/s 8714p/s 8714c/s 8714C/s friend..sahara
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

## Detection of Indicators and Telemetry

Offline cracking does not hit login services, so lockouts and failed logon dashboards stay quiet'


To detect look for similar running processes 

**Process creation:** Password cracking has a small set of well-known binaries and command patterns that we can look out for. A mix of process events, file activity, GPU signals, and network touches tied to tooling and wordlists. Our goal is to make the activity obvious without drowning in noise.

- Binaries and aliases: `john`, `hashcat`, `fcrackzip`, `pdfcrack`, `zip2john`, `pdf2john.pl`, `7z`, `qpdf`, `unzip`, `7za`, `perl` invoking `pdf2john.pl`.
- Command‑line traits: `--wordlist`, `-w`, `--rules`, `--mask`, `-a 3`, `-m` in Hashcat, references to `rockyou.txt`, `SecLists`, `zip2john`, `pdf2john`.
- Potfiles and state: `~/.john/john.pot`, `.hashcat/hashcat.potfile`, `john.rec`