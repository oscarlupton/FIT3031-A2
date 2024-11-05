## Prologue
This is the final assignment for FIT3031, in Semester 2 2024, written by Oscar Lupton. GitHub Copilot and Microsoft 365 Copilot for Enterprise were used for diagnosing issues with my VM, and for assisting with testing my configurations.
## 2 - Submission policy
![](/images/Pasted image 20241106000523.png)
![[images/Pasted image 20241106001647.png]]
`ded71fd4b4966d7323586274b941780a55ded6b4` (with errors?)
## 3 - Scenario
33979375 mod 3 = 1 = Clayton. Primary DC = Clayton.
## 4 - Secure network design and implementation <12 marks>
### Topology
![[images/Pasted image 20241104200847.png]]
**Clayton**: 10.200.10.0/24, gateway at 192.168.122.200 (WAN), 10.200.10.1 (LAN)
- Primary DC is here.
- `CLA-SERVER-01` at 10.200.10.3 (static)
- `CLA-CLIENT-01` at 10.200.10.2 (static)
**Peninsula**: 10.201.10.0/24, gateway at 192.168.122.201 (WAN), 10.201.10.1 (LAN)
- `PLA-CLIENT-01` at 10.201.10.2 (static)
**Caulfield**: 10.202.10.0/24, gateway at 192.168.122.202 (WAN), 10.202.10.1 (LAN)
- `CAU-CLIENT-01` at 10.202.10.2 (static)
**WAN**: 192.168.122.0/24, gateway at 192.168.122.1
- `External-Attacker` at 192.168.122.203 (static)
### `External-Attacker` setup
- Add Ubuntu VM to ISP switch. Client static IP config `192.168.122.203`, netmask `255.255.255.0`, gateway `192.168.122.1`, nameserver `8.8.8.8`.
- Install essential packages (`iproute2`, `ssh`, `lynx`, etc.)
### `CLAYTON` router
```
//NAT traversal for services
/ip firewall nat print //`ip firewall nat remove` existing records if applicable
/ip firewall nat add action=masquerade chain=srcnat out-interface=ether1 //masquerade for LAN->Internet access
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=22 protocol=tcp dst-address=10.200.10.3 dst-port=22 comment=ssh //SSH to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=25 protocol=tcp dst-address=10.200.10.3 dst-port=25 comment=smtp //Postfix SMTP to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=53 protocol=udp dst-address=10.200.10.3 dst-port=53 comment=dns //DNS to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=80 protocol=tcp dst-address=10.200.10.3 dst-port=80 comment=http //Apache HTTP to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=443 protocol=tcp dst-address=10.200.10.3 dst-port=443 comment=https //Apache HTTPS to WAN
/ip firewall nat print //verify

//Firewall restrictions for services
/ip firewall filter print //`ip firewall filter remove` existing records
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=80,443,25,22 //allow specific ports on firewall
/ip firewall filter add chain=input action=accept protocol=udp src-address=10.201.10.0/24 dst-port=53 //allow PLA DNS traffic
/ip firewall filter add chain=input action=accept protocol=udp src-address=10.202.10.0/24 dst-port=53 //allow CAU DNS traffic
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=179 action=accept //BGP rx
/ip firewall filter add chain=output action=accept protocol=tcp dst-port=179 action=accept //BGP tx
/ip firewall filter print //verify
```
### `CLA-SERVER-01`
#### `/etc/network/interfaces`
```
auto eth0
iface eth0 inet static
	address 10.200.10.3
	netmask 255.255.255.0
	gateway 10.200.10.1
	up echo nameserver 10.200.10.3 > /etc/resolv.conf
```
#### Setup
```bash
root@CLA-SERVER-01;/# echo 1.1.1.1 > /etc/resolv.conf
root@CLA-SERVER-01:/# apt install postfix bind9 apache2 nano ssh iputils-ping iproute2 dnsutils lynx -y
// **** [postfix] Initial setup ****
>Type: 2 - Internet site
>System mail name: 33979375.com
>Geographic area: 4 - Australia
>Time zone: 11 - Melbourne
root@CLA-SERVER-01:/# echo 10.200.10.3 > /etc/resolv.conf

// **** [bind9] DNS config ****
root@CLA-SERVER-01:/# nano /etc/bind/named.conf.options
options {
	directory "/var/cache/bind";
	recursion yes;
	dnssec-validation auto;
	allow-transfer {none;};
	allow-query {any;};
	listen-on {any;};
	forwarders {
		1.1.1.1;
		1.0.0.1;
	};
};
root@CLA-SERVER-01:/# nano /etc/bind/named.conf.local
//forward zone (-> domain)
zone "33979375.com" {
	type master;
	file "/etc/bind/db.33979375.com";
};
//reverse zone (-> ip)
zone "3.10.200.10.in-addr.arpa" {
	type master;
	file "/etc/bind/db.10";
};
root@CLA-SERVER-01:/# cp /etc/bind/db.local /etc/bind/db.33979375.com
root@CLA-SERVER-01:/# nano /etc/bind/db.33979375.com
$TTL	604800
@		IN		SOA		33979375.com.	root.33979375.com. (
							2			; Serial
							604800		; Refresh
							86400		; Retry
							2419200		; Expire
							604800 )	; Negative Cache TTL
;
@		IN		NS		33979375.com.
@		IN		A		10.200.10.3
www		IN		A		10.200.10.3
root@CLA-SERVER-01:/# cp /etc/bind/db.127 /etc/bind/db.10
root@CLA-SERVER-01:/# nano /etc/bind/db.10
$TTL	604800
@		IN		SOA		33979375.com.	root.33979375.com. (
							2			; Serial
							604800		; Refresh
							86400		; Retry
							2419200		; Expire
							604800 )	; Negative Cache TTL
;
@		IN		NS		33979375.com.
248		IN		PTR		33979375.com.
#Testing
root@CLA-SERVER-01:/# chmod -R 777 /var/cache/bind
root@CLA-SERVER-01:/# service named start

// **** [bind9] DNS server test ****
root@CLA-SERVER-01:/# dig @localhost 33979375.com

// **** [openssl] CA and server certificate creation ****
root@CLA-SERVER-01:/# nano /usr/lib/ssl/openssl.cnf
[policy_match]
Change all to optional
[CA_default]
dir = .
root@CLA-SERVER-01:/# mkdir pki
root@CLA-SERVER-01:/# cd pki
root@CLA-SERVER-01:/pki# openssl req -new -x509 -keyout ca.key -out ca.crt
>Enter PEM pass phrase: fit3031
>Country Name (2 letter code) [AU]:
>State or Province Name (full name) [Some-State]:VIC
>Locality Name (eg, city) []:Clayton
>Organization Name []:Monash University
>Organizational Unit Name []:FIT3031
>Common Name (e.g. server FQDN or YOUR name) []:33979375.com
>Email Address []:olup0002@student.monash.edu
root@CLA-SERVER-01:/pki# openssl genrsa -out server.pem 2048
root@CLA-SERVER-01:/pki# openssl req -new -key server.pem -out server.csr
[...]
// setting up a self-signing CA
root@CLA-SERVER-01:/pki# mkdir certs crl newcerts private csr
root@CLA-SERVER-01:/pki# touch index.txt
root@CLA-SERVER-01:/pki# echo 1000 > ./serial
root@CLA-SERVER-01:/pki# echo 1000 > ./crlnumber
root@CLA-SERVER-01:/pki# openssl ca -in server.csr -out server.crt -cert ca.crt -keyfile ca.key
[...]

// **** [apache2] Webpage config  ****
root@CLA-SERVER-01:/# nano /var/www/html/index.html //add "33979375" (student ID) to webpage

// **** [apache2] HTTP SSL config ****
root@CLA-SERVER-01:/pki# nano /etc/apache2/sites-available/default-ssl.conf
>SSLCertificateFile /pki/server.crt
>SSLCertificateKeyFile /pki/server.key
root@CLA-SERVER-01:/pki# a2enmod ssl
root@CLA-SERVER-01:/pki# a2ensite default-ssl
root@CLA-SERVER-01:/pki# chmod 777 -R /pki

// **** [postfix] SMTP TLS config ****
root@CLA-SERVER-01:/pki# openssl req -keyout 33979375.pem -out 33979375.cert -nodes -newkey rsa:2048 -days 365 -x509 -subj "/C=AU/ST=Victoria/L=Clayton/O=Monash/CN=33979375.com"
root@CLA-SERVER-01:/pki# postconf -e "smtpd_tls_cert_file=/pki/33979375.cert"
root@CLA-SERVER-01:/pki# postconf -e "smtpd_tls_key_file=/pki/33979375.pem"
root@CLA-SERVER-01:/pki# postconf -e "smtpd_use_tls=yes"
root@CLA-SERVER-01:/pki# cd ..

// **** [openssh] SSH server config ****
root@CLA-SERVER-01:/# adduser johnforge
[...] //"hunter2"

root@CLA-SERVER-01:/# service ssh start
root@CLA-SERVER-01:/# service apache2 start
root@CLA-SERVER-01:/# service postfix start

// **** [apache2] Web server test ****
root@CLA-SERVER-01:/# lynx https://33979375.com
[...] //trust the site

// **** [postfix] Mail server test ****
root@CLA-SERVER-01:/# telnet 33979375.com 25
[...] //terminal should read "Postfix ESMTP" or similar
```
## 5 - BGP <10 marks>
### Configuration
```
/routing bgp export
/routing bgp peer print

// **** Clayton router ****
/routing bgp instance set default as=3001 routerid=192.168.122.200 redistribute-connected=yes redistribute-other-bgp=yes comment="CLA"
/routing bgp network add network="10.200.10.0/24"
/routing bgp peer add name=PLA remote-address=192.168.122.201 remote-as=3002 comment=PEN
/routing bgp peer add name=CAU remote-address=192.168.122.202 remote-as=3003 comment=CAU

// **** Peninsula router ****
/routing bgp instance set default as=3002 routerid=192.168.122.201 redistribute-connected=yes redistribute-other-bgp=yes comment="PLA"
/routing bgp network add network="10.201.10.0/24"
/routing bgp peer add name=CLA remote-address=192.168.122.200 remote-as=3001 comment=CLA
/routing bgp peer add name=CAU remote-address=192.168.122.202 remote-as=3003 comment=CAU

// **** Caulfield router ****
/routing bgp instance set default as=3003 routerid=192.168.122.202 redistribute-connected=yes redistribute-other-bgp=yes comment="CAU"
/routing bgp network add network="10.202.10.0/24"
/routing bgp peer add name=CLA remote-address=192.168.122.200 remote-as=3001 comment=CLA
/routing bgp peer add name=PLA remote-address=192.168.122.201 remote-as=3002 comment=PEN
```
![[images/Pasted image 20241103183135.png]]
![[images/Pasted image 20241103183215.png]]
![[images/Pasted image 20241103183221.png]]
### Hijack
Tap all router links with Wireshark. Objective: use Peninsula router to hijack Clayton ASN. Caulfield connection will be disrupted.
```
/ip address add address=192.168.122.200 netmask=255.255.255.224 interface=ether1
```
This works because `PENINSULA` (an AS) announces the same address as `CLAYTON` but with a more specific prefix (27 > 24)
### Recovery
```
#Caulfield router
/routing filter add chain=in-200 prefix=192.168.122.201/24 prefix-length=25-32 action=discard
/routing bgp peer print
/routing bgp peer edit number=0 //select number for 192.168.122.201 (Peninsula)
>value-name: in-filter
>value = in-200
/routing bgp peer print
```
## 6 - VPN <15 marks>
### `CLAYTON` configuration <3 marks for showing traffic on Wireshark>
```
/ip ipsec profile add name="Intercampus" hash-algorithm=sha256 enc-algorithm=aes-256 dh-group=modp2048 lifetime=1d
/ip ipsec proposal add name="Intercampus" auth-algorithms=sha256 enc-algorithms=aes-256-gcm lifetime=8h

/ip ipsec peer add name="PLA" address=192.168.122.201 profile=Intercampus exchange-mode=ike2
/ip ipsec identity add peer=PLA auth-method=pre-shared-key secret="hunter2"
/ip ipsec policy add
	comment="PLA-bound traffic over VPN"
	src-address=10.200.10.0/24 dst-address=10.201.10.0/24
	proposal=Intercampus peer=PLA
	tunnel=yes action=encrypt level=require ipsec-protocols=esp

/ip ipsec peer add name="CAU" address=192.168.122.202 profile="Intercampus" exchange-mode=ike2
/ip ipsec identity add peer=CAU auth-method=pre-shared-key secret="hunter2"
/ip ipsec policy add
	comment="CAU-bound traffic over VPN"
	src-address=10.200.10.0/24 dst-address=10.202.10.0/24
	proposal=Intercampus peer=CAU
	tunnel=yes action=encrypt level=require ipsec-protocols=esp
```
![[images/Pasted image 20241103183927.png]]
### `PENINSULA` config <3 marks for showing traffic on Wireshark>
```bash
/ip ipsec profile add name="Intercampus" hash-algorithm=sha256 enc-algorithm=aes-256 dh-group=modp2048 lifetime=1d
/ip ipsec proposal add name="Intercampus" enc-algorithms=aes-256-gcm lifetime=8h

/ip ipsec peer add name="CLA" address=192.168.122.200 profile="Intercampus" exchange-mode=ike2
/ip ipsec identity add peer=CLA auth-method=pre-shared-key secret="hunter2"
/ip ipsec policy add comment="CLA-bound traffic over VPN" src-address=10.201.10.0/24 dst-address=10.200.10.0/24 proposal=Intercampus peer=CLA tunnel=yes action=encrypt level=require ipsec-protocols=esp

/ip ipsec peer add name="CAU" address=192.168.122.202 profile="Intercampus" exchange-mode=ike2
/ip ipsec identity add peer=CAU auth-method=pre-shared-key secret="hunter2"
/ip ipsec policy add comment="CAU-bound traffic over VPN" src-address=10.201.10.0/24 dst-address=10.202.10.0/24 proposal=Intercampus peer=CAU tunnel=yes action=encrypt level=require ipsec-protocols=esp
```
### `CAULFIELD` config <3 marks for showing traffic on Wireshark>
```
/ip ipsec profile add name="Intercampus" hash-algorithm=sha256 enc-algorithm=aes-256 dh-group=modp2048 lifetime=1d
/ip ipsec proposal add name="Intercampus" enc-algorithms=aes-256-gcm lifetime=8h

/ip ipsec peer add name="CLA" address=192.168.122.200 profile=Intercampus exchange-mode=ike2
/ip ipsec identity add peer=CLA auth-method=pre-shared-key secret="hunter2"
/ip ipsec policy add comment="CLA-bound traffic over VPN" src-address=10.202.10.0/24 dst-address=10.200.10.0/24 proposal=Intercampus peer=CLA tunnel=yes action=encrypt level=require ipsec-protocols=esp

/ip ipsec peer add name="PLA" address=192.168.122.201 profile="Intercampus" exchange-mode=ike2
/ip ipsec identity add peer="PLA" auth-method=pre-shared-key secret="hunter2"
/ip ipsec policy add comment="PLA-bound traffic over VPN" src-address=10.202.10.0/24 dst-address=10.201.10.0/24 proposal=Intercampus peer=PLA tunnel=yes action=encrypt level=require ipsec-protocols=esp
```
### IPsec installed security associations <2 marks per router>
```
#Clayton
/ip ipsec installed-sa print
[...]
#Peninsula
/ip ipsec installed-sa print
[...]
#Caulfield
/ip ipsec installed-sa print
[...]
```
## 7 - Firewall configuration <18 marks>
Rules (33979375 mod 4 = 3):
- DNS server accessible from all campuses (not WAN)
- Web server accessible anywhere (campus + WAN)
- LAN clients should be able to ping default gateway
- SSH should only be accessible from Clayton and WAN
- Mail server should only be accessible from Peninsula
### Updated `CLAYTON` config:
```bash
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=22 protocol=tcp dst-address=10.200.10.3 dst-port=22 comment=ssh  // SSH to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=25 protocol=tcp dst-address=10.200.10.3 dst-port=25 comment=smtp  // Postfix SMTP to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=53 protocol=udp dst-address=10.200.10.3 dst-port=53 comment=dns  // DNS to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=80 protocol=tcp dst-address=10.200.10.3 dst-port=80 comment=http  // Apache HTTP to WAN
/ip firewall nat add chain=dstnat action=dst-nat to-addresses=10.200.10.3 to-ports=443 protocol=tcp dst-address=10.200.10.3 dst-port=443 comment=https  // Apache HTTPS to WAN

/ip firewall nat add action=masquerade chain=srcnat out-interface=ether1 comment="NAT masq"
/ip firewall filter add chain=input action=accept protocol=udp dst-port=500,4500 comment="IKE, NAT-T"
/ip firewall filter add chain=input action=accept protocol=ipsec-esp comment="IPsec ESP"
/ip firewall filter add chain=input action=accept protocol=ipsec-ah comment="IPsec AH"
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=179 comment="BGP"

/ip firewall filter add chain=input action=accept protocol=icmp src-address=10.200.10.0/24 comment="Allow ping on LAN"

//Service controls
/ip firewall filter add chain=input action=accept protocol=udp src-address=10.200.10.0/24 dst-port=53 comment="Allow DNS from Clayton"
/ip firewall filter add chain=input action=accept protocol=udp src-address=10.201.10.0/24 dst-port=53 comment="Allow DNS from Peninsula"
/ip firewall filter add chain=input action=accept protocol=udp src-address=10.202.10.0/24 dst-port=53 comment="Allow DNS from Caulfield"
/ip firewall filter add chain=input action=accept protocol=tcp src-address=10.201.10.0/24 dst-port=25 comment="Allow SMTP from Peninsula"
/ip firewall filter add chain=input action=accept protocol=tcp src-address=10.200.10.0/24 dst-port=22 comment="Allow SSH from Clayton"
/ip firewall filter add chain=input action=accept protocol=tcp in-interface=ether1 src-address=!10.201.10.0/24 src-address=!10.202.10.0/24 dst-port=22 comment="Allow SSH from WAN (not Peninsula/Caulfield)"
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=80,443 comment="Allow HTTP/S from all"

/ip firewall filter add chain=forward action=accept out-interface=ether1 comment="Allow Internet access"
/ip firewall filter add chain=output action=accept out-interface=ether1 comment="Allow Internet access"
/ip firewall filter add chain=input action=drop comment="Drop all other input traffic"
/ip firewall filter add chain=forward action=drop comment="Drop all other forward traffic"

/ip firewall filter print
```
![[images/Pasted image 20241105021031.png]]
### `PENINSULA` config
```
/ip firewall nat add action=masquerade chain=srcnat out-interface=ether1 comment="NAT masq"
/ip firewall filter add chain=input action=accept protocol=udp dst-port=500,4500 comment="IKE, NAT-T"
/ip firewall filter add chain=input action=accept protocol=ipsec-esp comment="IPsec ESP"
/ip firewall filter add chain=input action=accept protocol=ipsec-ah comment="IPsec AH"
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=179 comment="BGP"

/ip firewall filter add chain=forward action=accept src-address=10.201.10.0/24 dst-address=10.200.10.0/24 comment="Allow traffic to Clayton"
/ip firewall filter add chain=forward action=accept out-interface=ether1 comment="Allow Internet access"
/ip firewall filter add chain=output action=accept out-interface=ether1 comment="Allow Internet access"

/ip firewall filter add chain=input action=accept protocol=icmp src-address=10.201.10.0/24 comment="Allow ping on LAN"

/ip firewall filter add chain=input action=drop comment="Drop all other input traffic"
/ip firewall filter add chain=forward action=drop comment="Drop all other forward traffic"
/ip firewall filter add chain=output action=drop comment="Drop all other output traffic"

/ip firewall filter print
```
![[images/Pasted image 20241105022421.png]]
### `CAULFIELD` config
```
/ip firewall nat add action=masquerade chain=srcnat out-interface=ether1 comment="NAT masq"

/ip firewall filter add chain=input action=accept protocol=udp dst-port=500,4500 comment="IKE, NAT-T"
/ip firewall filter add chain=input action=accept protocol=ipsec-esp comment="IPsec ESP"
/ip firewall filter add chain=input action=accept protocol=ipsec-ah comment="IPsec AH"
/ip firewall filter add chain=input action=accept protocol=input dst-port=179 comment="BGP"

/ip firewall filter add chain=forward action=accept src-address=10.202.10.0/24 dst-address=10.200.10.0/24 comment="Allow traffic to Clayton"
/ip firewall filter add chain=forward action=accept out-interface=ether1 comment="Allow Internet access"
/ip firewall filter add chain=output action=accept out-interface=ether1 comment="Allow Internet access"

/ip firewall filter add chain=input action=accept protocol=icmp src-address=10.202.10.0/24 comment="Allow ping on LAN"

/ip firewall filter add chain=input action=drop comment="Drop all other input traffic"
/ip firewall filter add chain=forward action=drop comment="Drop all other forward traffic"
/ip firewall filter add chain=output action=drop comment="Drop all other output traffic"

/ip firewall filter print
```
![[images/Pasted image 20241105021548.png]]
## 8 - Security analysis <12 marks>
### Can the firewall configuration be bypassed? <6 Marks>
Yes.
#### \[Yes] How can it be bypassed?
Port-based firewalls can be bypassed by communicating over an open port, but using a different protocol. For example, inbound traffic to Peninsula and Caulfield is permitted on `tcp://*:179`, `udp://*:500`, `udp://*:4500`, and via IPsec ESP and AH protocols on any port. All traffic is also accepted from Clayton, which in turn accepts all TCP traffic on ports 20, 80, and 443, barring port 22 traffic from Peninsula and Caulfield.

An easy out-of-the-box example is tunnelling; a Cloudflare tunnel runs over TCP on port 443, and would blend in with regular Web traffic. It may be possible to bypass this network's firewall/s by slipping non-Web traffic through these open ports. One could exploit the SSH/HTTP openings, establish persistence, then communicate back via an open port.
#### \[Yes] How to counter it?
Cutting down on the permitted intercampus traffic would help; add more port and protocol rules to keep it just to what's necessary (SSH, SMTP, etc). Splitting the server/s off to a separate subnet would also help with intracampus security breaches at Clayton. A separate DNS server could also be in place with a domain whitelist for the servers, to minimise the risk of unwanted outbound traffic.
### Discuss how the security of the network can be improved <6 Marks>
As above, the servers should be in a separate subnet, and the firewall rules should be more granular. A separate subnet may help with management, as network access has been super finnicky thus far (sometimes it's the rules, sometimes it's the system at large). Traffic analysis may also help, with an easy start being a DNS server with whitelisting. This could be scaled up to an application-layer firewall, which can restrict traffic in a more advanced manner through traffic analysis. This could be done with or without DPI, for example.
## 9 - IDS <15 marks>
### Configure IDS for servers
#### OVS configuration
```
root@CLA-OVS-01:/# ovs-vsctl add-br br0
root@CLA-OVS-01:/# ovs-vsctl add-port br0 eth0 //uplink
root@CLA-OVS-01:/# ovs-vsctl add-port br0 eth1 //IDS
root@CLA-OVS-01:/# ovs-vsctl add-port br0 eth2 //CLA-SERVER-01

root@CLA-OVS-01:/# ovs-vsctl -- --id=@m create Mirror name=m0 select-dst-port=eth2 output-port=eth1
root@CLA-OVS-01:/# ovs-vsctl -- set Bridge br0 mirrors=@m
```
### Detect an external TCP scan with IDS
```
root@CLA-IDS-01:/# apt update
root@CLA-IDS-01:/# apt install snort nano -y
>Address range for the local network: 10.200.10.0/24
root@CLA-IDS-01:/# nano /etc/snort/rules/local.rules
>config classification: icmp-event, Generic ICMP event, 3
>alert icmp any any -> any any (msg:"ICMP test detected"; GID:1; sid:10000001; rev:001; classtype:icmp-event;)
```
### Detect an external DoS attack on the Web server with IDS
```
root@CLA-IDS-01:/# nano /etc/snort/rules/local.conf

//SYN flood on port 80. `flags:S` = SYN
>alert tcp any any -> any 80 (msg:"SYN flood detected"; flags:S; threshold:type threshold, track by_src, count 50, seconds 10; sid:10000002; rev:001;)

//ICMP flood on any port
>alert icmp any any -> any any (msg:"ICMP flood detected"; threshold:type threshold, track by_src, count 50, seconds 10; sid:10000003; rev:001;)

//UDP flood on any port
>alert udp any any -> any any (msg:"UDP flood detected"; threshold:type threshold, track by_src, count 50, seconds 10; sid:10000004; rev:001;)
```
## 10 - Ethical conduct <10 marks>
1) Identify unethical activities a network user (staff/student) can perform in the network.
- Access anything Web-based. Send/receive emails of any kind. Deploy an encrypted network tunnel to the outside. Other stuff like that.
2) Develop an Ethical Network Usage policy with a list of guidelines to Monash staff and students.
This policy riffs off of the Monash University Information Technology Acceptable Use Procedure (last reviewed in July 2024), available [here](https://publicpolicydms.monash.edu/Monash/documents/1909280). The policy covers access, responsibilities, liberties, and compliance.
### Ethical Usage Policy
#### Introduction
Monash University provides IT resources to staff and students, which can be accessed both on- and off-premises. This policy governs the usage of these resources to ensure their integrity and reliability. By using the IT resources of the University, including network access via a personal or University device, you are agreeing to this Policy.
#### Access
- Access to the IT resources is restricted to authorised users only. Access is provisioned ad hoc and at the discretion of University or an authorised agent.
- Users must not access resources - including files, accounts, or devices - for which they are not authorised, and must not grant access without the clearance to do so.
#### Responsibilities
- Users must take reasonable care in securing their account, including protecting their passwords and utilising two-factor authentication.
- Users must take reasonable care with emails, messages, and other forms of electronic communications, to ensure privacy, copyright, and confidentiality are protected.
#### Liberties
- Users are permitted to use the IT resources of the University, including Internet access, for academic and work purposes. Users are also permitted to use Internet access for personal purposes at the discretion of the University.
- Unacceptable usage includes illegal activities as defined by law and/or University regulations, such as unauthorised commercial usage, distribution of pornographic material, and unauthorised penetration testing.
#### Compliance
- The University reserves the right to access and monitor IT resources, including devices, network traffic, and accounts.
- Contravention of this Policy can constitute misconduct, potentially resulting in disciplinary action and restriction of access to IT resources.
- IT resources may be accessed, monitored, and restricted to comply with law enforcement activities.
