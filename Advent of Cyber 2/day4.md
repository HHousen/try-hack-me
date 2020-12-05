# Day 4 - Santa's watching (Web Exploitation)

1. Given the URL "<http://shibes.xyz/api.php>", what would the entire wfuzz command look like to query the "breed" parameter using the wordlist "big.txt" (assume that "big.txt" is in your current directory)? `wfuzz -c -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ`

2. Use GoBuster (against the target you deployed -- not the shibes.xyz domain) to find the API directory. What file is there? `site-log.php`. Directory brute-forcing with `gobuster`: `gobuster dir -u 10.10.39.152 -t 100 -w /usr/share/wordlists/dirb/big.txt` finds `/api`. `site-log.php` is only file in `/api`.

3. Fuzz the date parameter on the file you found in the API directory. What is the flag displayed in the correct post?

    1. `cat wordlist.txt` (because "The sysadmin also told us that the API creates logs using dates with a format of YYYYMMDD"):

        ```
        20201100
        20201101
        20201102
        20201103
        20201104
        20201105
        20201106
        20201107
        20201108
        20201109
        20201110
        20201111
        20201112
        20201113
        20201114
        20201115
        20201116
        20201117
        20201118
        20201119
        20201120
        20201121
        20201122
        20201123
        20201124
        20201125
        20201126
        20201127
        20201128
        20201129
        20201130
        20201201
        20201202
        20201203
        20201204
        20201205
        20201206
        20201207
        20201208
        20201209
        20201210
        20201211
        20201212
        20201213
        20201214
        20201215
        20201216
        20201217
        20201218
        20201219
        20201220
        20201221
        20201222
        20201223
        20201224
        20201225
        20201226
        20201227
        20201228
        20201229
        20201230
        20201231
        ```

    2. `wfuzz -c -z file,wordlist.txt 10.10.39.152/api/site-log.php?date=FUZZ` output:

        ```
        ********************************************************
        * Wfuzz 3.1.0 - The Web Fuzzer                         *
        ********************************************************

        Target: http://10.10.39.152/api/site-log.php?date=FUZZ
        Total requests: 62

        =====================================================================
        ID           Response   Lines    Word       Chars       Payload                                                                                        
        =====================================================================

        000000001:   200        0 L      0 W        0 Ch        "20201100"                                                                                     
        000000003:   200        0 L      0 W        0 Ch        "20201102"                                                                                     
        000000014:   200        0 L      0 W        0 Ch        "20201113"                                                                                     
        000000007:   200        0 L      0 W        0 Ch        "20201106"                                                                                     
        000000013:   200        0 L      0 W        0 Ch        "20201112"                                                                                     
        000000011:   200        0 L      0 W        0 Ch        "20201110"                                                                                     
        000000015:   200        0 L      0 W        0 Ch        "20201114"                                                                                     
        000000006:   200        0 L      0 W        0 Ch        "20201105"                                                                                     
        000000010:   200        0 L      0 W        0 Ch        "20201109"                                                                                     
        000000009:   200        0 L      0 W        0 Ch        "20201108"                                                                                     
        000000004:   200        0 L      0 W        0 Ch        "20201103"                                                                                     
        000000008:   200        0 L      0 W        0 Ch        "20201107"                                                                                     
        000000005:   200        0 L      0 W        0 Ch        "20201104"                                                                                     
        000000002:   200        0 L      0 W        0 Ch        "20201101"                                                                                     
        000000017:   200        0 L      0 W        0 Ch        "20201116"                                                                                     
        000000026:   200        0 L      1 W        13 Ch       "20201125"                                                                                     
        000000030:   200        0 L      0 W        0 Ch        "20201129"                                                                                     
        000000028:   200        0 L      0 W        0 Ch        "20201127"                                                                                     
        000000012:   200        0 L      0 W        0 Ch        "20201111"                                                                                     
        000000025:   200        0 L      0 W        0 Ch        "20201124"                                                                                     
        000000021:   200        0 L      0 W        0 Ch        "20201120"                                                                                     
        000000027:   200        0 L      0 W        0 Ch        "20201126"                                                                                     
        000000029:   200        0 L      0 W        0 Ch        "20201128"                                                                                     
        000000024:   200        0 L      0 W        0 Ch        "20201123"                                                                                     
        000000023:   200        0 L      0 W        0 Ch        "20201122"                                                                                     
        000000020:   200        0 L      0 W        0 Ch        "20201119"                                                                                     
        000000033:   200        0 L      0 W        0 Ch        "20201202"                                                                                     
        000000022:   200        0 L      0 W        0 Ch        "20201121"                                                                                     
        000000018:   200        0 L      0 W        0 Ch        "20201117"                                                                                     
        000000016:   200        0 L      0 W        0 Ch        "20201115"                                                                                     
        000000037:   200        0 L      0 W        0 Ch        "20201206"                                                                                     
        000000031:   200        0 L      0 W        0 Ch        "20201130"                                                                                     
        000000019:   200        0 L      0 W        0 Ch        "20201118"                                                                                     
        000000045:   200        0 L      0 W        0 Ch        "20201214"                                                                                     
        000000036:   200        0 L      0 W        0 Ch        "20201205"                                                                                     
        000000044:   200        0 L      0 W        0 Ch        "20201213"                                                                                     
        000000040:   200        0 L      0 W        0 Ch        "20201209"                                                                                     
        000000046:   200        0 L      0 W        0 Ch        "20201215"                                                                                     
        000000042:   200        0 L      0 W        0 Ch        "20201211"                                                                                     
        000000041:   200        0 L      0 W        0 Ch        "20201210"                                                                                     
        000000043:   200        0 L      0 W        0 Ch        "20201212"                                                                                     
        000000039:   200        0 L      0 W        0 Ch        "20201208"                                                                                     
        000000047:   200        0 L      0 W        0 Ch        "20201216"                                                                                     
        000000038:   200        0 L      0 W        0 Ch        "20201207"                                                                                     
        000000048:   200        0 L      0 W        0 Ch        "20201217"                                                                                     
        000000053:   200        0 L      0 W        0 Ch        "20201222"                                                                                     
        000000061:   200        0 L      0 W        0 Ch        "20201230"                                                                                     
        000000062:   200        0 L      0 W        0 Ch        "20201231"                                                                                     
        000000050:   200        0 L      0 W        0 Ch        "20201219"                                                                                     
        000000035:   200        0 L      0 W        0 Ch        "20201204"                                                                                     
        000000032:   200        0 L      0 W        0 Ch        "20201201"                                                                                     
        000000034:   200        0 L      0 W        0 Ch        "20201203"                                                                                     
        000000054:   200        0 L      0 W        0 Ch        "20201223"                                                                                     
        000000059:   200        0 L      0 W        0 Ch        "20201228"                                                                                     
        000000055:   200        0 L      0 W        0 Ch        "20201224"                                                                                     
        000000052:   200        0 L      0 W        0 Ch        "20201221"                                                                                     
        000000060:   200        0 L      0 W        0 Ch        "20201229"                                                                                     
        000000051:   200        0 L      0 W        0 Ch        "20201220"                                                                                     
        000000056:   200        0 L      0 W        0 Ch        "20201225"                                                                                     
        000000058:   200        0 L      0 W        0 Ch        "20201227"                                                                                     
        000000057:   200        0 L      0 W        0 Ch        "20201226"                                                                                     
        000000049:   200        0 L      0 W        0 Ch        "20201218"                                                                                     

        Total time: 1.444222
        Processed Requests: 62
        Filtered Requests: 0
        Requests/sec.: 42.92966
        ```

    3. `20201125` has 13 characters while the others have 0, so `20201125` is probably correct: `curl 10.10.39.152/api/site-log.php?date=20201125` to get `THM{D4t3_AP1}`
