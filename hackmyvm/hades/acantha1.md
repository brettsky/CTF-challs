We are now logged in as acantha


With the mission

```
################
# MISSION 0x02 #
################

## EN ##
The user alala has left us a program, if we insert the 6 correct numbers, she gives us her password!
```

We cat create a python script to try all six number combinations 

We have to create scripts in the tmp directory

We do that using this command to copy a file into the tmp directory

touch /tmp/guessit.py

we then add the code using 

nano /tmp/guessit.py


we then use this code to create a process to try every combination. 


```
import subprocess

# Path to the binary
binary_path = "./guess"

# Loop through all 6-digit PINs
for pin in range(1000000):
    # Format the PIN to be 6 digits, with leading zeros if necessary
    pin_str = str(pin).zfill(6)
    print(f"Trying PIN: {pin_str}")

    # Use subprocess to run the binary and provide input
    process = subprocess.Popen([binary_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Send the PIN as input to the binary
    output, error = process.communicate(input=(pin_str + '\n').encode())

    # Decode the output to make it human-readable
    output_decoded = output.decode()

    # Check if the binary's output contains the failure message
    if "NO" not in output_decoded:
        print(f"Correct PIN found: {pin_str}")
        break

```

we then make it executable: 
``` 
chmod +x /tmp/guessit.py
 ```

 we then run it and start guessing the password 

 ```
ython3 /tmp/guessit.py
Trying PIN: 000000
Trying PIN: 000001
Trying PIN: 000002
Trying PIN: 000003
Trying PIN: 000004
Trying PIN: 000005
Trying PIN: 000006
Trying PIN: 000007
Trying PIN: 000008
Trying PIN: 000009
Trying PIN: 000010
Trying PIN: 000011
Trying PIN: 000012



 ```



Password for the guess file is 013370


./guess password is 013370 and gives us the pass for the next user alala DsYzpJQrCEndEWIMxWxu