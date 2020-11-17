# python-teams
Pythonic Implementation Of Collaborative Software

### Reason for its creation.
After using many collaborative platforms such as repl.it, Microsoft Teams, etc, I realised they all involved the same things.
 - Creation of an account
 - Creation of teams with other users
 - Shared code bases
 - Features that help users program together, text each other, set deadlines, update calendars, etc.
 
 I therefore used some basic python3 and flask to write this program which seeks to implement all these features soon.It has basic functionality up and running and is open for contribution.
 
 ### Setup
  - Install the dependencies with pip
  ```python3
 pip3 install -r requirements.txt
 ```
 - Start the flask server
 ```bash
 python3 app.py
 ```
 
 #### Notes:
  - The server can be reconfigured to run with your ipv6 address.This will enable other devices connected to the same network as your system to connect to your flask server
  - In app .py do:
  ```python3
  socket.run(app, host='your_ipv6_address', port='your_port_number_choice')
  ```
  - Determine IPV6 Address
  - To determine your ipv6 address on linux run ifconfig.Under your wireless card's(eg.)WLAN0) descriptions output, search for inet and the number that follows is your ipv6 address
![Image of ifconfig](https://github.com/druzgeorge/python-teams/blob/main/screenshots/ifconfig_screenshot.png) 
- To determine IPv6 address on Windows
```bash
Type “ipconfig/all” on the blinking cursor then press [Enter]. NOTE: You will find the IPv6 Address network details under the Ethernet adapter Local Area Connection section.
```
- To determine IPv6 address on Mac
- Try ifconfig
```bash
ifoncig
```
- Try the method here : https://www.macobserver.com/tmo/article/how-to-obtain-the-ipv6-address-of-your-mac-and-ipad
#### Features:
##### Home Page:
- Contains notifications of user
![Image of notifications](https://github.com/druzgeorge/python-teams/blob/main/screenshots/home.png)
##### Messaging:
- Contains contact list and message div for sending messages to users
![Image of messaging](https://github.com/druzgeorge/python-teams/blob/main/screenshots/messaging.png)
##### Projects:
- Contains created projects and their statuses
![Image of projects](https://github.com/druzgeorge/python-teams/blob/main/screenshots/projects.png)
##### Calendar:
![Image of calendar](https://github.com/druzgeorge/python-teams/blob/main/screenshots/calendar.png)


 ~ malimba.
