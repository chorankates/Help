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


## flag
```
user:
root:
```
