# Day 11 - The Rogue Gnome (Networking)

1. What type of privilege escalation involves using a user account to execute commands as an administrator? `Vertical`

2. What is the name of the file that contains a list of users who are a part of the sudo group? `sudoers`

3. Use SSH to log in to the vulnerable machine like so: `ssh cmnatic@10.10.154.154`. Input the following password when prompted: `aoc2020`

4. Enumerate the machine for executables that have had the SUID permission set. Look at the output and use a mixture of [GTFObins](https://gtfobins.github.io/) and your researching skills to learn how to exploit this binary. You may find uploading some of the enumeration scripts that were used during today's task to be useful. Run `find / -perm -u=s -type f 2>/dev/null` to find executables that have the SUID bit set. `/bin/bash` has the SUID bit set.

5. Use this executable to launch a system shell as root. What are the contents of the file located at /root/flag.txt? Use the `-p` argument (according to [GTFOBins](https://gtfobins.github.io/gtfobins/bash/))by running `bash -p` to gain root. Run `cat /root/flag.txt` to get `thm{2fb10afe933296592}`.
