'''
A number of challenges will require you to create solutions which are more efficiently solved by making use of a programming language to automate and perform the computations. For this purpose, we recommend to make use of Python as well as complementary libraries such as requests and pwntools.

If you are not sure where to start with Python, we recommend the introductory Python 101 for Hackers course.

Click the ‘START CHALLENGE’ button to the right of this text description to start a socket challenge. Utilise a programming language to interface with the socket and automate solving 500 simple addition problems to receive the flag. Take care when interfacing with unknown remote services - '\n' is not the only way to end
'''

from pwn import *

URL = "35acf8de52b4f7c8.247ctf.com"
PORT = 50267

# [+] Opening connection to 54774aadc5a56c41.247ctf.com on port 50488: Done
r = remote(URL,PORT)

# b'Welcome to the 247CTF addition verifier!\r\n'
print(r.recvline())
# b'If you can solve 500 addition problems, we will give you a flag!\r\n'
print(r.recvline())

for i in range(500):
	problem = r.recvline().decode("utf-8") 	# What is the answer to 64 + 491?

	print(problem)

	split = problem.split() # ['What', 'is', 'the', 'answer', 'to', '64', '+', '491?']

	a = int(split[5])		# '64' -> 64
	b = int(split[7].strip('?')) 	# '491?' -> 491
	print(a,b)
	answer = (str(a+b)+'\r\n').encode("utf-8")
	print(answer)
	r.sendline(answer)
	print(answer)
	r.recvline() # b'Yes, correct!\r\n'print(f"Solved {count} of 500")

# b'247CTF{6ae15c0aeb{censored}1eb0dda5cab1}\r\n'
flag = r.recvline().decode("utf-8").strip('\r\n')

# 247CTF{6ae15c0aeb{censored}1eb0dda5cab1}
print(flag)

# [*] Closed connection to 54774aadc5a56c41.247ctf.com port 50488
r.close()
