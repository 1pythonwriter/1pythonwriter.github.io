---
layout: post
title: "Syskron CTF 2020"
date: 20-10-29
categories: ctf writeups
---
Writeup Author: 1pythonwriter

While studying for a few tests over the weekend, I decided to attempt a few syskronCTF challenges. Although I didn't solve to many, I believe I did a decent job in my limited time.

## Welcome Letter
This challenge was a simple sanity check. Simply open the pdf file given welcome-letter-1.pdf and find the flag in the letter
## Vulnerable RTOS, Deadly Malware, Security Framework, and Check Digit (Trivia)
The trivia challenges can all be solved with a simple google search:
-  syskronCTF{URGENT/11}
-  syskronCTF{Triton}
-  syskronCTF{ID-PR-DE-RS-RC}
-  syskronCTF{ISO/IEC-7812}


## Redacted News
-We get an image with part of the text censored:
![image](/assets/redacted.png)
In order to find the flag, it looks like we need to remove the alpha channel from the image. This can be done with a 
simple python script:
```python
from PIL import Image
Image.open('redacted.png').convert('RGB').save('solved.png')
```
we get:
![image](/assets/solved.png)
flag: syskronCTF{d0-Y0u-UNdEr5TaND-C2eCh?}
## Security Headers
This challenge tells us to check the HTTP response headers on www.senork.de.
Simply use:
```
curl -I https://www.senork.de
```
and we get the flag: syskronCTF{y0u-f0und-a-header-flag}
## Dos Attack
Googling "Siemens Dos Attack Malware" or something similar will yield the name of the malware: Industroyer.
flag: syskronCTF{Industroyer}
## Leak Audit
For this challenge SQL came in handy. To find the flag, we needed to find how many employee records were in the file, any duplicate
passwords, and how many records were protected with bcrypt.
For this challenge, I first opened the .db file in [DB Browser for SQLite](https://sqlitebrowser.org/ "sqlitebrowser") and scrolled to the bottom, getting the answer to the first question:
376
Next, to find any duplicate passwords, we use the query:
```
SELECT password, COUNT(password)
FROM personal
GROUP BY password
HAVING COUNT(password) > 1
```
we get: mah6geiVoo

Finally, in order to find the number of passwords protected with bcrypt, we can simply look at the recent passwords. Those that start with "$2b$10$" are encrypted with bcrypt. (21 passwords)

Our flag is: syskronCTF{376_mah6geiVoo_21}


## Reflection
syskronCTF 2020 was a great experience for me. Although I had limited time to spend working on challenges, I was able to improve my knowledge of sql, "Google-Fu", and simply have a fun time. I will hopefully be able to spend a lot-more time on ctfs in the future, as I came extremely close to solving multiple other challenges (now that I learn from writeups), despite my limited time.
