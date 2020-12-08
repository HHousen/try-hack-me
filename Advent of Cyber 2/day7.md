# Day 7 - The Grinch Really Did Steal Christmas (Networking)

1. Open "pcap1.pcap" in Wireshark. What is the IP address that initiates an ICMP/ping? `10.11.3.2`

2. If we only wanted to see HTTP GET requests in our "pcap1.pcap" file, what filter would we use? `http.request.method == GET`

3. Now apply this filter to "pcap1.pcap" in Wireshark, what is the name of the article that the IP address "10.10.67.199" visited? `Reindeer-of-the-Week`. Filter by `http.request.method == GET && ip.addr == 10.10.67.199` and look for `/posts/` (due to hint). The answer can be found in the info section or by following the HTTP stream.

4. Let's begin analysing "pcap2.pcap". Look at the captured FTP traffic; what password was leaked during the login process? `plaintext_password_fiasco`. Filter by `tcp.port == 21` since we are looking for FTP traffic and FTP uses tcp on port 21. Find packet in info where it says `PASS` and follow TCP stream.

5. Continuing with our analysis of "pcap2.pcap", what is the name of the protocol that is encrypted? `SSH`. This is seen in the file without any filters.

6. Analyse "pcap3.pcap" and recover Christmas! What is on Elf McSkidy's wishlist that will be used to replace Elf McEager? Follow `tcp.stream eq 4`, which looks like a file download. Click File > Export Objects > HTTP, then choose `christmas.zip` and save it. Unzipping `christmas.zip` reveals `elf_mcskidy_wishlist.txt` with the following contents:

    ```
    Wish list for Elf McSkidy
    -------------------------
    Budget: £100

    x3 Hak 5 Pineapples
    x1 Rubber ducky (to replace Elf McEager)
    ```

    So, the answer is `Rubber ducky`.
