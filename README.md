# Grey-Hack-Scripts
Scripts for the game Grey Hack

mapkit: vulnerability scanner that saves the vulnerabilities to a txt file in the map /targets/lib(service_version) it asks if you want to attack the target, mapkit can be used as standalone.

mapkit-bounce: vulnerability scanner that saves the vulnerabilities to a txt file in the map /targets/lib(service_version) it asks if you want to attack the target, for daemonmail+mapwatcher added bounce to stay "hidden"

daemonmail: scans mail, que's IP addresses launches mapkit and harvests banks from target with file vulnerabilities, not a standalone needs mapkit to work.

Mapwatcher: Does what is says watches the map targets and when daemonmail drops in the queue.txt with the IP's it got from your mail it launches mapkit

USE daemonmail, mapwatcher, and mapkit-bounce, to have a automated suite and improve your work flow!

Vector: Brute force password if a Admin forced guest privileges or you have only guest shell exploits you can drop vector and your vecpass folder with your vecpass.txt files in the guest map of your target and run it wait and you get the password never took longer than 30 seconds for me and drops you in root shell. CAN TAKE LONGER THAN 30 SECONDS! Depends on the password of the machine itself!
Passwords list updated with 14725 passwords use this list PLUS the 6 vecpass files that vecpassgen made you have the most success!

Vecpassgen: Generates LARGE password lists 15K words per file for vector so u have more chance to crack a password (when the first vecpass.txt file fails) IT DOES TAKE A MOMENT!
use the vecpassgen in game for the other files and delete the master_list.txt file

Credits vector TO JWFRAUSTRO 
https://github.com/jwfraustro/Vector-Greyhackgame/blob/main/Vector.src


maybe more to come
