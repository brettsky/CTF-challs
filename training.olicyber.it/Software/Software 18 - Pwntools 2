In this challenge you will see how to use the packing and unpacking functions that pwntools offers.

These are useful when developing exploits as they allow you to convert, for example, memory addresses in numeric form into their representation in little or big endian bytes.

Pwntools offers wrappers for the structpython library (which offers struct.pack).

p64(num, endianness="little", ...)Packs a 64-bit integer
p32(num, endianness="little", ...)Packs a 32-bit integer
u64(data, endianness="little", ...)Unpacks 64-bit integers
u32(data, endianness="little", ...)Unpacks 32-bit integers
For example:

p64(0x401020) -> b"\x20\x10\x40\x00\x00\x00\x00\x00"
u32(b"\x00\x50\x40\x00") -> 0x405000
You can find more information in the relevant documentation

This challenge's binary will ask you to perform some conversion operations using pwntools' packing functions.

You can connect to the remote service with the command:

nc software-18.challs.olicyber.it 13001


1 . Connect to the remote service and see the challenge (nc software-18.challs.olicyber.it 13001)

    We see the challenge is 

    *****************************************************************
* Welcome to the second Pwntools challenge                        *
* You will receive a list of numbers and you will have to return them to me          *
* packed at 64 or 32 bits                                          *
* If you are fast enough, you will get the flag                      *
* You will have to complete 100 steps in 10 seconds                     *
************************* ****************************************...
 Send any character to start ...


 *****************************************************************

 To send any character to start we use the following code:
 