# Network Intrusion Detection and Response

### IDS

An Intrusion Detection System (IDS) is a security solution designed to monitor and analyze network or system activities for signs of malicious activity, unauthorized access, or policy violations. It detects threats such as malware, unauthorized access attempts, or abnormal behavior and generates alerts or logs for further investigation. IDS can be classified into two types: Network-based IDS (NIDS), which monitors network traffic, and Host-based IDS (HIDS), which focuses on activity within individual devices. While IDS are primarily used for detection and alerting, they do not block threats but provide valuable insights for security teams to respond to potential attacks.

### Snort

Snort is an open-source network intrusion detection and prevention system (NIDS/NIPS) used to monitor and analyze network traffic for suspicious activity and potential security threats. It captures packets from the network, inspects them using predefined rules, and generates alerts or blocks malicious traffic based on signature-based or anomaly detection. Snort can operate in various modes, including packet capture, intrusion detection, and prevention, making it versatile for real-time network monitoring and attack prevention. Its active community continuously updates its rule sets, enabling it to detect a wide range of known attacks such as DDoS, SQL injection, and buffer overflows. However, configuring Snort for optimal performance requires expertise, and it may consume significant system resources in high-traffic environments.

## Practical

We will use 3 VMs for this demonstration:

**IDS (ubuntu):** 10.0.2.15/24

**Attacker (kali):** 10.0.2.20/24

**Victim (ubuntu):** 10.0.2.3/24

Make sure all VMs are on the same network. For that create a new network and configure each VM network to this adapter.

![image](https://github.com/user-attachments/assets/8e30f4d9-f0bc-4f1c-b8f5-591f9a9a39d9)

Assign static ip to all for the practical demonstration. 

## Installing and Configuring Snort

Start by updating and upgrading the Ubuntu machine. Then install snort using command
\# sudo apt install snort

![image](https://github.com/user-attachments/assets/281bf9fc-49ff-4e21-9dff-cbb2311581d4)

![image](https://github.com/user-attachments/assets/5484a60e-68ec-4d7e-8735-0687c906c3a7)

Check ip and interface and use the same in snort configuration

![image](https://github.com/user-attachments/assets/e460ef9e-e53d-4070-a0d9-03e00e1d85d8)

Check successful installation by checking version.

![image](https://github.com/user-attachments/assets/5547f2af-5f96-4a8f-bc46-e58f791f1d31)

**Libpcap:** used to capture traffic and is what wireshark uses.

### Promiscuous Mode

Promiscuous mode is a network interface mode where the network interface card (NIC) receives all the traffic on the network, regardless of its destination. Normally, a NIC will only capture packets addressed to its own MAC address or broadcast packets, but in promiscuous mode, it listens to and processes all packets on the network segment it is connected to.

Enable promiscous mode on interface. When running a virtual machine move to network settings and set promiscuous mode to “allow all” else if not a VM then run the following command

\# sudo ip link set enp0s3 promisc on. This will enable the mode.

![image](https://github.com/user-attachments/assets/1a129c37-9fab-43fe-bbeb-833223057818)

## Configuration

The conf file for snort is located in /etc/snort directory

![image](https://github.com/user-attachments/assets/54acee4b-46f4-4c7f-9bb6-8149f2351880)

Always create a backup file before making changes to the configuration file. Here snort1.conf is the backup file. Now open up the configuration file and start making the required changes

![image](https://github.com/user-attachments/assets/bbea8879-a865-4fbf-8dd5-88280aa03d9e)

Specify the subnet or the network snort will be detecting the traffic on.

![image](https://github.com/user-attachments/assets/632d025e-e1bf-4efd-afe3-0fcffd5bb5eb)

Snort also allows to specify hosts that might be part on infrastructure.

![image](https://github.com/user-attachments/assets/54a11b9e-624b-4f19-b017-55af10958524)

We can change all of these to our network ones. Next we also have ports where the web servers can be run. We can also modify these to our needs.

![image](https://github.com/user-attachments/assets/69ebe38f-a0ac-4e09-821c-c70b387b59d4)

Scroll down to the bottom of the file to the rules section.

Here we can specify the actual rules file containing rules you want to use. Local.rules file is the one where we create our own rules, which is created by default and is empty

![image](https://github.com/user-attachments/assets/8dddbaba-cad9-46a7-8087-033ec0ffd17c)

To start snort in self-test mode to test configuration file

![image](https://github.com/user-attachments/assets/de1aea56-29f3-48f9-9651-f4a25dddd2f3)

![image](https://github.com/user-attachments/assets/9c3287b6-4baf-4ce3-943f-44d7a5cb9d6b)

Commenting out the custom community rules if we want to write our own.

![image](https://github.com/user-attachments/assets/85662699-7c3e-4d9e-8fb2-d7e9d1a08002)

So the only rules now that will be executed are in those that are in the local.rules file

Now if we run : \# sudo snort –T –i enp0s3 –c /etc/snort/snort.conf no duplicate errors will be shown

![image](https://github.com/user-attachments/assets/cf539ff0-eeba-49d4-a50f-4b276ee96c0c)

However, for this practical we will use these community rules. So there is no need to comment them out.

## Wireshark Installation

### Wireshark

Wireshark is a widely used, open-source network protocol analyzer that allows users to capture and inspect network traffic in real-time. It provides detailed insights into the data exchanged across networks by displaying packet-level information for various protocols such as TCP, UDP, HTTP, and DNS. Wireshark helps network administrators, security professionals, and developers troubleshoot network issues, analyze performance, detect malicious activities, and debug communication problems. With its powerful filtering capabilities, Wireshark enables users to dissect network traffic, identify anomalies, and ensure security by offering comprehensive packet capture, analysis, and visualization tools.

\# sudo apt-get install wireshark

![image](https://github.com/user-attachments/assets/0a4e39f4-3d0d-4cd9-a878-1adb6f551843)

For starting snort in IDS mode use the command:
\# sudo snort –A console –q –c /etc/snort/snort.conf –i enp0s3

Checking status

![image](https://github.com/user-attachments/assets/c952160a-b966-4595-9e6c-2b6bb25637ea)

Checking if snort is detecting traffic and logging. Pinging IDS with kali VM

![image](https://github.com/user-attachments/assets/e06a74e6-eeec-4a57-92d0-2edd8490e216)

On IDS alerts are being generated

![image](https://github.com/user-attachments/assets/8282114b-3560-4fe3-93a5-1095c19e9aca)

## Testing Malicious Traffic

We will generate malicious traffic towards any victim machine on the network and the IDS will detect this traffic

![image](https://github.com/user-attachments/assets/f61fba4a-5baf-4c29-bba0-4e8435aa826f)

Set Victim IP: 10.0.2.3

![image](https://github.com/user-attachments/assets/b1a62014-dfb7-41b4-97c9-2cb320a75f24)

In IDS

![image](https://github.com/user-attachments/assets/754a4608-7e6d-4806-995c-6aa4f003be18)


*   _01/18-09:29:33.082772 \[\*\*\] \[1:1418:11\] SNMP request tcp \[\*\*\] \[Classification: Attempted Information Leak\] \[Priority: 2\] {TCP} 10.0.2.20:45009 -> 10.0.2.3:161_

**Rule ID:** \[1:1418:11\]

**Traffic Type:** TCP

**Source:** 10.0.2.20

**Destination:** 10.0.2.3:161 (SNMP Port)

**Classification:** Attempted Information Leak

**Priority:** 2

SNMP (Simple Network Management Protocol) is used for monitoring and managing devices in a network. The alert suggests an SNMP request was sent to 10.0.2.3. Snort is flagging this because if the request is unauthorized, it could be an attacker probing for SNMP-accessible devices.

*   _01/18-09:29:33.085390 \[\*\*\] \[1:1420:11\] SNMP trap tcp \[\*\*\] \[Classification: Attempted Information Leak\] \[Priority: 2\] {TCP} 10.0.2.20:32983 -> 10.0.2.3:162_

Port 162 is used for SNMP Traps (asynchronous alerts sent by devices). This alert indicates a device is sending an SNMP trap to 10.0.2.3.

*   _01/18-09:29:34.133348 \[\*\*\] \[1:1421:11\] SNMP AgentX/tcp request \[\*\*\] \[Classification: Attempted Information Leak\] \[Priority: 2\] {TCP} 10.0.2.20:40623 -> 10.0.2.3:705_

Port 705 (SNMP AgentX) is used for communication between SNMP master and sub-agents.This alert means 10.0.2.20 attempted to communicate with 10.0.2.3 using SNMP AgentX. Attackers sometimes use SNMP misconfigurations to extract information.

## Analyzing Packets Using Wireshark

Capture the traffic and analyze the above alerts

Filter ip.dst==10.0.2.3 && tcp.dstport==161 and analyze the packet

![image](https://github.com/user-attachments/assets/58a57594-c68c-4f4e-a78d-bb01fd2f2cd1)

ip.dst==10.0.2.3 && tcp.dstport==163

![image](https://github.com/user-attachments/assets/1876dfb7-c3fb-4db9-8e93-cc811b9a9cab)

ip.dst==10.0.2.3 && tcp.dstport==705

![image](https://github.com/user-attachments/assets/4fc0dba2-e2ed-459b-824a-b76188a4ede2)

## Responding to Detected Intrusions

Respond to detected alerts from snort by implementing network defenses. We have reviewed and identified the alerts above so now we will set up network defense by setting rules in iptables

### Iptables

iptables is a command-line utility in Linux used for configuring and managing network traffic rules within the kernel’s built-in firewall framework. It allows administrators to define rules that control the flow of network packets based on criteria such as IP addresses, ports, protocols, and packet state. By specifying rules for incoming, outgoing, and forwarded traffic, \*\*iptables\*\* can block, allow, or modify packets, providing a powerful tool for securing systems and networks. It operates using a set of tables (filter, nat, mangle, etc.) that define the actions to be taken on packets in various network scenarios, such as packet filtering, network address translation (NAT), and packet logging.

![image](https://github.com/user-attachments/assets/49a08b67-9e72-494a-b4fb-738e4ec43cc8)

We added the rule 2 times lets delete one

![image](https://github.com/user-attachments/assets/77224ad1-c2dc-4089-8fb9-86a65edcd544)

We can also block the ports on the victim to strengthen the security

![image](https://github.com/user-attachments/assets/c275a29b-bafb-4e7d-ab8f-9755b53b2142)

### Conclusion

We have set up a Network Intrusion Detection System (NIDS), analyzed network traffic, and responded to security incidents. By implementing Snort on a dedicated IDS VM, we monitored network activity, detected unauthorized access attempts, and took preventive actions to secure the network.
Metasploit allowed us to simulate real-world attacks and assess the effectiveness of our defenses. The final step involved incident response, where we implemented firewall rules to block attacker and documented the security event.
By completing this, we developed essential skills in network security, intrusion detection, traffic analysis, and incident response, reinforcing the importance of proactive monitoring and defense mechanisms in cybersecurity.
