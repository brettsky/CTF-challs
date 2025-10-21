Level one gives us some rules for the challenge going forward in the read me and mission.txt



Readme
```
Hi hax0r,
Welcome to HMVLab Chapter 2: Hades!
This is a slightly more advanced CTF than Chapter 1 where you will continue to practice your Linux and CTF skills
so let's keep messing around! :)
Remember that the home of each user is in /pwned/USER and in it you will find a file called mission.txt which will contain
the mission to complete to get the password of the next user.
It will also contain the file flagz.txt, which if you are registered at https://hackmyvm.eu you can enter to participate in the ranking (optional).
And to continue the improvisation, there are more secret levels and hidden flags: D
You will not have write permissions in most folders so if you need to write a script or something
use the /tmp folder, keep in mind that it is frequently deleted ...

And last (and not least) some users can modify the files that are in the
folder /www, these files are accessible from http://hades.hackmyvm.eu so if you get a user
that can modify the file /www/limbo.txt, you can put a message and it will be reflected in http://hades.hackmyvm.eu/limbo.txt.

If you have questions/ideas or want to comment anything you can join
to our Discord: https://discord.gg/DxDFQrJ

```

mission.txt 
```
################
# MISSION 0x01 #
################

## EN ##
User acantha has left us a gift to obtain her powers.

```

we use the command find / -perm -4000 2>/dev/null

to find a SUID binary we can run called /opt/gift_hacker 

This now gives us a shell in the acantha user and we can cat the pass word 

cat /pazz/acantha_pass.txt 

cat /pazz/acantha_pass.txt

mYYLhLBSkrzZqFydxGkn
