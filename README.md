# Configuring Snort

## Objective


The objective of this project/lab is to practice network traffic analysis using Snort with a focus on configuring alerts and logging capability. 

### Skills Learned

- Gained knowledge of IPS/IDS capability and use cases
- Writing basic rules in Snort
- Installing and Configuring Snort
- Using Vim text editor
- Generating and logging alerts with Snort
- Viewing Snort logs in Wireshark
- Installing OpenSSH

### Tools Used

- Snort 2.9.20
- Oracle VirtualBox
- Vim
- Wireshark

### Environments

- Kali Linux 2025.4
- Windows 10 Pro (22H2)
- Ubuntu Desktop 24.04.3 LTS

## Steps

### Pre-requisites:

Create an Ubuntu desktop VM in VirtualBox that we will use to host Snort

Ensure the minimal hardware requirements are met for Snort by changing the settings in VirtualBox

Ensure that the server and other machines are on the correct NAT network in VirtualBox

<img width="627" height="505" alt="snort_use" src="https://github.com/user-attachments/assets/3848274f-45a9-4b60-99e8-d0a7d0ec2980" />

*Network Diagram*

### Snort 2 IDS/IPS installation:

<img width="987" height="57" alt="Screenshot 2025-12-24 160813" src="https://github.com/user-attachments/assets/9e36dff2-0342-4b54-9ee1-f75c4aaf3173" />

*Ref 1: Before anything, it's a good idea to run "sudo apt-get update && sudo apt-get upgrade -y"*

This will check for new packages and install new package versions

Next, we will install Snort using "sudo apt-get install snort -y"

<img width="755" height="106" alt="Screenshot 2025-12-25 160144" src="https://github.com/user-attachments/assets/cf5ac276-f293-4702-9260-3ecef1b2c09f" />

*Ref 2: After this, we will need to provide our local IP address range*

<img width="801" height="112" alt="Screenshot 2025-12-25 160108" src="https://github.com/user-attachments/assets/505a1db2-19db-4c1c-a558-ee5f1db6b6b1" />

*Ref 3: In this case, we can see by running "ip addr" that our local range is 192.168.25.0/24*

Enter the information and continue

<img width="868" height="239" alt="Screenshot 2025-12-28 153246" src="https://github.com/user-attachments/assets/5edf3f37-9bf4-438f-85be-1621403a7317" />

*Ref 4: We can confirm installation and version with "snort --version"*

Now we will change our network interface into permisicuos mode

This will essentially allow our machine to receive all data on the network, not just information addressed to our NIC's MAC address

<img width="787" height="99" alt="Screenshot 2025-12-25 160752" src="https://github.com/user-attachments/assets/a98f6345-072e-4eb1-84a9-c3149519a980" />

*Ref 5: Run "sudo ip link set enp0s3 promisc on"*

Note that individual interface names will be different

<img width="804" height="146" alt="Screenshot 2025-12-25 160853" src="https://github.com/user-attachments/assets/f7926402-99b2-471b-ba54-98eae4aa2f30" />

*Ref 6: With "ip addr" we can  see that promiscuous mode is on*

<img width="571" height="299" alt="promisc" src="https://github.com/user-attachments/assets/1bfdf199-467a-4a50-a508-e0e5e6fd4ec5" />

*Ref 7: We will also want to ensure that promiscuous mode is allowed within the network adapter settings in VirtualBox*

Run "sudo apt-get install vim -y" to ensure we can edit the Snort config file

To access the file, run "sudo vim /etc/snort/snort.conf"

<img width="525" height="87" alt="Screenshot 2025-12-25 162027" src="https://github.com/user-attachments/assets/b54bdc5d-2f6d-4e13-84ec-e3b4f675563f" />

*Ref 8: Going through the file, we will change the $HOME_NET value to our default gateway address (192.168.25.0/24)*

exit vim with ":wq" (Write quit)

Snort now knows the network that we want to monitor

To test our configuration file, Snort actually has a built-in self-test mode

<img width="907" height="54" alt="Screenshot 2025-12-28 164128" src="https://github.com/user-attachments/assets/596c81dd-a4a6-4e5b-a0da-52cce85efd6e" />

*Ref 9: To do this, we will run "sudo snort -T -i enp0s3 -c /etc/snort/snort.conf"*

<img width="652" height="117" alt="Screenshot 2025-12-28 164528" src="https://github.com/user-attachments/assets/5b444e91-fc90-407c-a9ee-00efe95da0d3" />

*Ref 10: With a successful validation, we can now take a look at the sections above*

<img width="571" height="341" alt="Screenshot 2025-12-28 164558" src="https://github.com/user-attachments/assets/7544d47b-5de7-4a24-94b1-000306fa000b" />

*Ref 11: This section provides valuable information on the rules that were scanned*

### Writing rules in Snort:

To practice writing rules, we will first disable rules provided by Snort and the community

<img width="665" height="43" alt="Screenshot 2025-12-29 163124" src="https://github.com/user-attachments/assets/463fdb53-d924-410c-8323-37fa829fc279" />

*Ref 12: To easily do this, we will enable line numbers for our root user in Vim with "sudo vim /root/.vimrc"*

We will then add "set number" ENTER "syntax on"

<img width="654" height="301" alt="Screenshot 2025-12-29 163359" src="https://github.com/user-attachments/assets/5a1141cb-1534-42b1-902c-b9978e0f76e7" />

*Ref 13: When we open the config file again, we can now see that the lines are numbered*

<img width="310" height="53" alt="Screenshot 2025-12-29 164657" src="https://github.com/user-attachments/assets/c5dac7af-165f-4b91-b40d-24fee8090a6d" />

*Ref 14: We will now comment out all of the Snort/Community rules with ":597,717s/^/#"*

<img width="458" height="521" alt="Screenshot 2025-12-29 164821" src="https://github.com/user-attachments/assets/0b61e704-514d-4299-bbb0-8bac1d4895c4" />

*Ref 15: We can now see that all of the rules are commented out*

Now run the self-test mode again

<img width="1213" height="169" alt="Screenshot 2025-12-29 165212" src="https://github.com/user-attachments/assets/832d8a68-380b-4bbf-86f5-b78d680cd3c8" />

*Ref 16: We can see that our commenting worked*

<img width="441" height="31" alt="Screenshot 2025-12-29 173836" src="https://github.com/user-attachments/assets/1ff543cf-35aa-4bef-8cf5-6a7f2a67ac33" />

*Ref 17: Access the local rules file with "sudo vim /etc/snort/rules/local.rules"*

For proof of concept, let's create a simple rule that alerts when any ICMP traffic is identified

<img width="963" height="196" alt="Screenshot 2025-12-29 174153" src="https://github.com/user-attachments/assets/bf2e2d9b-d752-43ac-941a-1d7af559319c" />

*Ref 18: In the local.rules file we will add "alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)*

### Running Snort and generating traffic:

We will now generate some alerts

In VirtualBox, create two other machines on the network

I will use Kali and Windows 10 because they already exist from a previous lab/project

Ensure that they are either using DHCP through VirtualBox or they are statically assigned to the network 192.168.25.0

For lab purposes, it makes sense to statically assign settings

<img width="688" height="235" alt="Screenshot 2026-01-01 191333" src="https://github.com/user-attachments/assets/9a7d4f6b-962c-48b6-ae55-36ef35b2cefa" />

*Ref 19: Kali IPv4 settings*

<img width="404" height="255" alt="netplan" src="https://github.com/user-attachments/assets/73aa5789-daf3-4e20-9b74-dfe12174e8e1" />

*Ref 20: Ubuntu static configuration using netplan*

<img width="391" height="340" alt="windowsIP" src="https://github.com/user-attachments/assets/080516d2-4f0c-424d-9070-7223246b54f6" />

*Ref 21: Windows static configuration*

<img width="784" height="37" alt="Screenshot 2026-01-01 195156" src="https://github.com/user-attachments/assets/ae934683-33b8-4f8c-b79a-7eba71ca5543" />

*Ref 22: With the other machines up and running, we will now start Snort with "sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf"*

We are running in Alert mode in quiet operation, specifying the log directory, the config file, and the interface

<img width="392" height="90" alt="Screenshot 2026-01-01 195432" src="https://github.com/user-attachments/assets/a9be134e-9006-4046-b6cc-fd01023d5761" />

*Ref 23: From our Windows machine, we will ping our Kali machine*

<img width="960" height="471" alt="Screenshot 2026-01-01 195545" src="https://github.com/user-attachments/assets/0bff89c3-691e-43ca-ad66-45b71a58d606" />

*Ref 24: We can now see the ping being detected by Snort, which is using our custom rule from earlier*

We can see the ICMP request and response

Now, let's write another rule using SSH

### Generating alerts with SSH:

<img width="616" height="204" alt="Screenshot 2026-01-02 175739" src="https://github.com/user-attachments/assets/09d89b8a-b281-4479-8986-83444ed29723" />

*Ref 25: We can confirm that OpenSSH is installed on the Kali machine either by checking the /bin directory or by simply typing ssh*

<img width="378" height="368" alt="Screenshot 2026-01-02 180230" src="https://github.com/user-attachments/assets/6c89afa8-8278-40d6-8d39-e51ecf07e19d" />

*Ref 26: On the Windows machine, we can see under settings^system^optional features, that the OpenSSH client is installed*

<img width="978" height="220" alt="Screenshot 2026-01-02 184928" src="https://github.com/user-attachments/assets/eba5357d-fc41-4224-ab79-2ac75083d47c" />

*Ref 27: Now that we have confirmed that OpenSSH is installed, add "alert tcp any any -> $HOME_NET 22 (msg:"SSH Authentication Attempt"; sid:1000002; rev:1;) to the local.rules file yet again*

<img width="841" height="466" alt="Screenshot 2026-01-02 184943" src="https://github.com/user-attachments/assets/d3be4905-fd13-45fb-9009-ccb3c35eb6c4" />

*Ref 28: We can also use the web-based tool, Snorpy, to easily create rules*

Start Snort again with "sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf"

<img width="302" height="129" alt="SSH_start" src="https://github.com/user-attachments/assets/f6f9a2ff-752d-4fb4-a267-001be2e91db2" />

*Ref 29: Ensure that SSH is running on Kali by running "sudo systemctl start ssh"*

<img width="386" height="89" alt="Screenshot 2026-01-02 185641" src="https://github.com/user-attachments/assets/a5f6e923-5b54-4bb6-a963-b90cb6dc6106" />

*Ref 30: Now we will make an SSH connection from the Windows machine to the Kali Machine*

<img width="1204" height="328" alt="Screenshot 2026-01-02 185831" src="https://github.com/user-attachments/assets/57833db4-7885-4bb6-95eb-b0c8f5c7e18b" />

*Ref 31: We can yet again see the alerts being generated from our rule in Snort*

### Viewing and using logging:

<img width="704" height="177" alt="Screenshot 2026-01-03 181844" src="https://github.com/user-attachments/assets/4751f42e-2a6b-41f3-9bee-731d17c85fb7" />

*Ref 32: All of the logs are saved under /var/log/snort*

Being that both of our rules are in alert mode, Snort basically logged a packet capture instead of just the rules created

We can see the various logs generated from our packet capture*

<img width="1213" height="146" alt="Screenshot 2026-01-03 184015" src="https://github.com/user-attachments/assets/1303fdbe-4684-4365-a6bc-e8552aaacb3f" />

*Ref 33: If we open the capture in Wireshark, we can actually view the traffic information from our ping earlier (I should note that this log contains all traffic traversing the network, similar to tcpdump)*

Although our ping is the only traffic on the network, if there were other traffic on the network, it would also appear in this capture, not just the alert we generated

<img width="1123" height="140" alt="Screenshot 2026-01-03 185116" src="https://github.com/user-attachments/assets/370be22c-f6d4-4ca5-911c-7633afb2146d" /> <img width="1137" height="35" alt="Screenshot 2026-01-03 185343" src="https://github.com/user-attachments/assets/e4543bd6-d94e-44f7-b276-36f322fa32b5" />

*Ref 34: To log only the alerts generated and not all network traffic, simply change the alert mode to "fast" instead of "console"*

<img width="1040" height="69" alt="Screenshot 2026-01-03 185628" src="https://github.com/user-attachments/assets/4a1fdb04-ae71-482b-b1ca-f21e305e0382" />

*Ref 35: Now, if we generate alerts, we can see that they are logged into a file called alert within /var/log/snort*

<img width="1193" height="190" alt="Screenshot 2026-01-03 185718" src="https://github.com/user-attachments/assets/95715817-dccf-4851-af4d-acdcb8b4238a" />

*Ref 36: Viewing the alert file with nano, we can see the alert generated*

This is useful because logs can now be forwarded into a SIEM like Splunk for further analysis























