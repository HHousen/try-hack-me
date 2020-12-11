# Day 10 - Don't be sElfish! (Networking)

1. Question #1 Using enum4linux, how many users are there on the Samba server (`MACHINE_IP`)?

    1. Install [`enum4linux`](https://tools.kali.org/information-gathering/enum4linux) with `sudo apt install enum4linux`.
    
    2. Run `enum4linux -U 10.10.209.199` to get:

        ```
        index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: elfmcskidy       Name:   Desc: 
        index: 0x2 RID: 0x3ea acb: 0x00000010 Account: elfmceager       Name: elfmceager        Desc: 
        index: 0x3 RID: 0x3e9 acb: 0x00000010 Account: elfmcelferson    Name:   Desc: 

        user:[elfmcskidy] rid:[0x3e8]
        user:[elfmceager] rid:[0x3ea]
        user:[elfmcelferson] rid:[0x3e9]
        ```
    
    3. There are `3` users on the share.

2. Question #2 Now how many "shares" are there on the Samba server? Run `enum4linux -S 10.10.209.199` to get:

    ```
    Sharename       Type      Comment
    ---------       ----      -------
    tbfc-hr         Disk      tbfc-hr
    tbfc-it         Disk      tbfc-it
    tbfc-santa      Disk      tbfc-santa
    IPC$            IPC       IPC Service (tbfc-smb server (Samba, Ubuntu))
    SMB1 disabled -- no workgroup available

    [+] Attempting to map shares on 10.10.209.199
    //10.10.209.199/tbfc-hr Mapping: DENIED, Listing: N/A
    //10.10.209.199/tbfc-it Mapping: DENIED, Listing: N/A
    //10.10.209.199/tbfc-santa      Mapping: OK, Listing: OK
    //10.10.209.199/IPC$    [E] Can't understand response:
    NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
    ```

    There are `4` shares.

3. Question #3 Use *smbclient* to try to login to the shares on the Samba server (MACHINE_IP). What share doesn't require a password? Try `smbclient //10.10.209.199/tbfc-santa` for each share and press enter without entering a password. We can access `tbfc-santa` without a password, so `tbfc-santa` is the answer.

4. Question #4 Log in to this share, what directory did ElfMcSkidy leave for Santa? Run `ls` and see directory called `jingle-tunes`.
