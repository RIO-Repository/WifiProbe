# Sniffer.py
 This Python script uses the Scapy library to sniff Wi-Fi probe requests on a specified interface. It detects and prints out unique SSIDs (network names) from these probe requests in real-time. This capability makes it useful for passive Wi-Fi network monitoring and analysis.

# To Run This Tool

### Step 1

```bash
   sudo su
```
'sudo su' switches the user to the superuser (root), granting elevated privileges necessary for tasks like sniffing Wi-Fi packets and configuring network interfaces.


### Step 2

```bash
   ifconfig
```
Specifically, 'ifconfig' will help identify the interface name (e.g., 'wlan0') that the script should use for sniffing Wi-Fi traffic. Once identified, the script can then pass this interface name to Scapy's sniff function to start monitoring Wi-Fi probe requests on that interface.


### Step 3

```bash
   ifconfig wlan0 down 
```
'ifconfig wlan0 down' disables the WLAN interface named 'wlan0', effectively stopping its operation. This command could be used in the project to temporarily halt Wi-Fi monitoring on the specified interface.


### Step 4

```bash
   iwconfig wlan0 mode monitor 
```
Running 'iwconfig wlan0 mode monitor' sets the WLAN interface named 'wlan0' into monitor mode. In monitor mode, the interface can capture all Wi-Fi traffic passing through it, including probe requests and other network packets. This step is crucial for passive Wi-Fi monitoring and analyzing network activity.


### Step 5

```bash
     ifconfig wlan0 up
```
ifconfig wlan0 up will enable the WLAN interface named 'wlan0', allowing it to resume normal operation. In the context of this project, it will restore the interface to its active state, enabling it to send and receive Wi-Fi packets. This step is necessary after setting the interface to monitor mode to ensure that the device can connect to Wi-Fi networks again.


### Step 6

```bash
     'python sniffer.py'
```
Running 'python sniffer.py' will execute the Python script named 'sniffer.py'. This script utilizes Scapy to sniff Wi-Fi probe requests on a specified interface, printing out unique SSIDs (network names) in real-time. It provides a passive method for monitoring nearby Wi-Fi networks and devices probing for them.





