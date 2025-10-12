#!/usr/bin/env python3
# Import the pwntools library
from pwn import *
import ast

HOST = "software-17.challs.olicyber.it"
PORT = 13000
# Connect to the server
r = remote(HOST, PORT)

def add_numbers(resp_bytes):
    string = resp_bytes.decode("UTF-8")
    num_list = ast.literal_eval(string) # this line evaluates the string and returns a list 
    print(num_list)
    sum_answer = str(sum(num_list)).encode()
    return sum_answer

def recv_isolate_num_list(): # this line receives the list of numbers from the server
    isolate_pre = r.recvuntil(b"numeri\n") # this line receieves until the word "numeri" is found
    print(isolate_pre)
    isolate_list = r.recvuntil(b"]") # this line receieves until the word "]" is found  

    print(isolate_list) # 
    return isolate_list

def send_answer(answer_bytes): # this line sends the answer to the server
    print(answer_bytes)
    r.sendline(answer_bytes)

def main():
    '''
    remote(hostname, port) opens a socket and returns an object
    that can be used to send and receive data on the socket  
    '''
    # Receive data from the server
    data = r.recvuntil(b"iniziare ...")
    print(data)
    # Send the newline
    r.sendline(b"")
    # Run a for loop to complete the steps
    for x in range(1,11):
        print(f"=====STEP {x}=====")
        list = recv_isolate_num_list()
        add = add_numbers(list)
        send = send_answer(add)
 
    # Receive the flag
    last_data = r.recv(1024)
    print(last_data)
    last_data2 = r.recv(1024)
    print(last_data2)
    r.close()

if __name__ == "__main__":
    main()