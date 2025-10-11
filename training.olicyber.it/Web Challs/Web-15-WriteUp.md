Web 15 - Web Technologies: External Resources

wget -r -l 1 -np http://web-15.challs.olicyber.it/ | cat web-15.challs.olicyber.it/* | grep -oP 'flag\{[^}]+\}'

I use wget cat and grep to get the files associated with that url 

It automatically uses grep to find the flag 

![Level 15 screenshot](https://raw.githubusercontent.com/brettsky/CTF-challs/main/training.olicyber.it/Web%20Challs/screenshots/Level15ScreenShot.png)
