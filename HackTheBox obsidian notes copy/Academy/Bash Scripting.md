#HTB #bash #coding
Bourne again shell

Scripting vs Programing languages - we dont need to compile bash scripts. 

## Shebang

The shebang line is always at the top of each script and always starts with "`#!`". This line contains the path to the specified interpreter (`/bin/bash`) with which the script is executed.


## Special Variables

Special variables use the [Internal Field Separator](https://bash.cyberciti.biz/guide/$IFS) (`IFS`) to identify when an argument ends and the next begins. Bash provides various special variables that assist while scripting. Some of these variables are:

|**Special Variable**|**Description**|
|---|---|
|`$#`|This variable holds the number of arguments passed to the script.|
|`$@`|This variable can be used to retrieve the list of command-line arguments.|
|`$n`|Each command-line argument can be selectively retrieved using its position. For example, the first argument is found at `$1`.|
|`$$`|The process ID of the currently executing process.|
|`$?`|The exit status of the script. This variable is useful to determine a command's success. The value 0 represents successful execution, while 1 is a result of a failure.|
```
if [ $# -eq 0 ]
then
    echo -e "You need to specify the target domain.\n"
    echo -e "Usage:"
    echo -e "\t$0 <domain>"
    exit 1
else
    domain=$1
fi

<SNIP>
```

$<n> is a special variable that will print out the command line argument of the number associated with it. In the above example it is printing out the name of the script since $0 is reserved for the script name

if [[ $var == *"ERmFRMVZ0U2paTlJYTkxDZz09Cg"* ]]; then 
echo  $var | tail -c 20


Condition to check if a variable contains that string then prints out the last 20 characters using tail

We can also calculate the length of the variable. Using this function ${#variable}, every character gets counted, and we get the total number of characters in the variable.

`tee`, we transfer the received output and use the pipe (`|`) to forward it to `tee`. The "`-a` / `--append`" parameter ensures that the specified file is not overwritten but supplemented with the new results. At the same time, it shows us the results and how they will be found in the file.