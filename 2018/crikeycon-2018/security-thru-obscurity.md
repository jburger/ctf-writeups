# "Security Through Obscurity!"
## From: Crikey Con 2018 CTF
## Points: 300
### Location: https://crikeyconctf.dook.biz/challenges#Security%20Through%20Obscurity!
#### Last updated April 4 2018

Also a fun challenge, and I was kind of excited to work against a .NET binary because that's been a major focus of my career thus far.

This one was a case of knowing the right tools for the job though.

## Runtime behaviour

- This challenge does some pretty funky things but ultimately, it just wants the right password sent to it.
- .NET 4.x? Console app
- Various anti-brute force methods exist, so it is pretty clear this isn't that kind of challenge.

## Tools used:

1. a .NET decompiler (Redgate Reflector, ILSpy, Jetbrains Dotpeek) any of these would work, 
   but I've been using dotpeek
   
2. [Linqpad](http://www.linqpad.net/)

## Method

> GENERIC SPOILER IS GENERIC! 

First up, load the binary in to the decompiler, you'll note that a fair amount of ceremony occurs in order to match your input 
password with a decrypted string. This string, is hashed in a complex way and apparently salted(?) (using a fixed salt -_-)

The library has a decrypt method that can be used to reverse the password 'hash' to yield the flag string. 

I just copied all the relevant parts of the decompiled source code into linqpad and ran it to reveal the clear text flag.

Plugging this into the console application rewards you with a popular tune :)

## Video

[![.NET assembly reversing ctf - spoiler](--thumb--)](--vid--)


