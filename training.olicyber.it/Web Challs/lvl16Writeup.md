We have to create a spider that will crawl the webpages and get the flag.

We did this challenge within kali linux and developed the script in Vscode- copying it into nano 

first run wget to get a list of links:

wget --no-clobber --no-parent --spider -r http://web-16.challs.olicyber.it/ 2>&1 | grep '^--' | awk '{print $3}' | tee urls2.txt


We then got a list of urls and wrote lvl16-Brett.py to parse through each webpage using get requests and regex to find the flag. 