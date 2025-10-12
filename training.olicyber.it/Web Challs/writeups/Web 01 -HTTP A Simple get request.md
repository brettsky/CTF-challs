This series of introductory web security challenges will introduce the HTTP protocol and the main web technologies commonly associated with it, as well as some simple tools for interacting with it.

The individual challenges will follow the jeopardy model , focusing on obtaining flags .

The examples and explanations proposed will refer to the Python language and its standard library, as well as the requestsand libraries BeautifulSoup, which are therefore recommended to install to best follow this path.

Installing recommended libraries on Debian and Ubuntu Linux:

sudo apt install python3-requests python3-bs4
On Windows systems, manually install the Python interpreter obtainable from the official Python project website and run it in the command prompt

pip install requests bs4
Designed to facilitate access to hypertext documents, the HyperText Transfer Protocol (HTTP) is now used to transfer information of all kinds to and from remote servers over the Internet. This information is organized into resources , identified by address strings called URLs (Unified Resource Locators), and the basic operations performed on these resources are called HTTP verbs .

The simplest of these verbs, GET, is used to retrieve a resource from a remote server. The goal of this challenge is to retrieve the text of the root resource of the web server 01.challs.olicyber.it, identified by the URL http://web-01.challs.olicyber.it/

It is recommended to use the library's getrequests function .



To complete this challenge we have to send a get requst to the server. We will do this using the requests module in python