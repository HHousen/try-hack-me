# Day 7 - What's Under the Christmas Tree? (Networking)

1. When was Snort created? `1998`.

2. Using Nmap on 10.10.102.49, what are the port numbers of the three services running? (Please provide your answer in ascending order/lowest -> highest, separated by a comma). `80,2222,3389`. Run `nmap 10.10.102.49` and get:

    ```
    Nmap scan report for 10.10.102.49
    Host is up (0.11s latency).
    Not shown: 997 closed ports
    PORT     STATE SERVICE
    80/tcp   open  http
    2222/tcp open  EtherNetIP-1
    3389/tcp open  ms-wbt-server

    Nmap done: 1 IP address (1 host up) scanned in 24.36 seconds
    ```

3. Run a scan and provide the `-Pn` flag to ignore ICMP being used to determine if the host is up. `nmap -Pn 10.10.102.49`.

4. Experiment with different scan settings such as `-A` (scan the host to identify services running by matching against Nmap's database with OS detection) and `-sV` (scan the host using TCP and perform version fingerprinting) whilst comparing the outputs given.

    1. Output of `nmap -sV 10.10.102.49`:

        ```
        Nmap scan report for 10.10.102.49
        Host is up (0.11s latency).
        Not shown: 997 closed ports
        PORT     STATE SERVICE       VERSION
        80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
        2222/tcp open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
        3389/tcp open  ms-wbt-server xrdp
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


        Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
        Nmap done: 1 IP address (1 host up) scanned in 23.35 seconds
        ```

    2. Output of `nmap -A 10.10.102.49`:

        ```
        Nmap scan report for 10.10.102.49
        Host is up (0.11s latency).
        Not shown: 997 closed ports
        PORT     STATE SERVICE       VERSION
        80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
        |_http-generator: Hugo 0.78.2
        |_http-server-header: Apache/2.4.29 (Ubuntu)
        |_http-title: TBFC&#39;s Internal Blog
        2222/tcp open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   2048 cf:c9:99:d0:5c:09:27:cd:a1:a8:1b:c2:b1:d5:ef:a6 (RSA)
        |   256 4c:d4:f9:20:6b:ce:fc:62:99:54:7d:c2:b4:b2:f2:b2 (ECDSA)
        |_  256 d0:e6:72:18:b5:20:89:75:d5:69:74:ac:cc:b8:3b:9b (ED25519)
        3389/tcp open  ms-wbt-server xrdp
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

        Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
        Nmap done: 1 IP address (1 host up) scanned in 32.33 seconds
        ```

5. Use Nmap to determine the name of the Linux distribution that is running, what is reported as the most likely distribution to be running? `Ubuntu`. Run `sudo nmap -O 10.10.102.49`, which states there are "no exact OS matches for host" but using service fingerprinting we can see that the machine is running an Ubuntu version of SSH.

6. Use Nmap's Network Scripting Engine (NSE) to retrieve the "HTTP-TITLE" of the webserver. Based on the value returned, what do we think this website might be used for? `blog`. From the output of `nmap -A 10.10.102.49` we can see that the title is `TBFC's Internal Blog` or you can get the "HTTP-TITLE" with the [http-title script](https://nmap.org/nsedoc/scripts/http-title.html) by running `nmap --script http-title 10.10.102.49`.

7. Now use different scripts against the remaining services to discover any further information about them. Let's try running all the `vuln` scripts: `nmap --script vuln 10.10.102.49`.

    ```
    Nmap scan report for 10.10.102.49
    Host is up (0.11s latency).
    Not shown: 997 closed ports
    PORT     STATE SERVICE
    80/tcp   open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    |   /js/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    |   /page/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    |_  /src/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    | http-internal-ip-disclosure: 
    |_  Internal IP Leaked: 10
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    2222/tcp open  EtherNetIP-1
    3389/tcp open  ms-wbt-server
    |_rdp-vuln-ms12-020: ERROR: Script execution failed (use -d to debug)
    |_ssl-ccs-injection: No reply from server (TIMEOUT)
    |_sslv2-drown: 

    Nmap done: 1 IP address (1 host up) scanned in 52.36 seconds
    ```
