# Auto-Enum.py
Enumeration Automation!

I did not recreate the wheel with this one. I simply automated it! Alot of the time when you get stuck doing a CTF it is due to missing something during enumeration. This should help to an extent, by covering some of the basic enumeration tasks. This includes your portscanning, directory bruteforcing, and sub-domain bruteforcing. As an added bonus, it will also grab the ports' services and versions and run a google search for exploits (this only returns links, so finding the right one is still on you).

Currently FFUF is configured to search for files with the extensions of .php and .txt. If you still cannot find anything it may be worth taking another run at. Adding all possibilities or even 5 caused the wordlist to be over 1000000 attempts and takes way to long to complete.

In addition to that, when FFUF runs in the background, it still shows output and makes your terminal goofy. I put a little effort into suppressing that output, but over all, it doesn't really affect anything and I perfer being able to see the status update.

Everything is run with subprocesses and the python script will finish before the FFUF does. If you want to stop any of the background processes, you will need to kill the process as ctrl+c will not work.

If you have any useful additions, I am open to them, but cannot guarantee they will be made. If you want to make additions, you can reachout to me.


Do not use Auto-Enum for anything that is illegal! This is not a 'stealthy' approch and is made for CTFs. I will not be held liable for any damages caused by the use Auto-Enum.
