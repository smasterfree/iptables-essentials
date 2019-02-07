<h2 align="center">Iptables Essentials: Common Firewall Rules and Commands</h2>

中文翻译，iptables 命令使用指南，by example 的 cheatsheet。


<br>

<p align="center">
  <a href="https://github.com/trimstray/iptables-essentials/tree/master">
    <img src="https://img.shields.io/badge/Branch-master-green.svg?longCache=true"
        alt="Branch">
  </a>
  <a href="http://www.gnu.org/licenses/">
    <img src="https://img.shields.io/badge/License-GNU-blue.svg?longCache=true"
        alt="License">
  </a>
</p>

<div align="center">
  <sub>Created by
  <a href="https://twitter.com/trimstray">trimstray</a> and
  <a href="https://github.com/trimstray/iptables-essentials/graphs/contributors">
    contributors
  </a>
</div>

<br>

<p align="center">
Found on the Internet - All in One List.
</p>

## :ballot_box_with_check: Todo

- [ ] Add useful Iptables configuration examples
- [ ] Add useful Kernel Settings (sysctl) configuration examples
- [ ] Add links to useful external resources
- [ ] Add advanced configuration examples, commands, rules

****

## Table Of Content

- [Tools to help you configure Iptables](#tools-to-help-you-configure-iptables)
- [Manuals/Howtos/Tutorials](#manualshowtostutorials)
- [How it works?](#how-it-works)
- [Iptables Rules](#iptables-rules)
    * [保存规则](#保存规则)
          * [Debian Based](#debian-based)
          * [RedHat Based](#redhat-based)
    * [列出所有规则（verbose）](#列出所有规则verbose)
    * [列出所有规则，带行号](#列出所有规则带行号)
    * [列出所有active规则](#列出所有active规则)
    * [列出所有 INPUT chain 规则（表格形式）](#列出所有-input-chain-规则表格形式)
    * [列出 INPUT chain 详情](#列出-input-chain-详情)
    * [列出packet个数，大小等信息](#列出packet个数大小等信息)
    * [列出 INPUT，OUTPUT 规则，带行号](#列出-inputoutput-规则带行号)
    * [删除规则（通过行号）](#删除规则通过行号)
    * [删除规则（通过详情）](#删除规则通过详情)
    * [清空所有规则（！）](#清空所有规则)
    * [清空所有chains](#清空所有chains)
    * [清空单个chain](#清空单个chain)
    * [加入一条规则](#加入一条规则)
    * [允许 loopback 连接](#允许-loopback-连接)
    * [允许 Established and Related Incoming Connections](#允许-established-and-related-incoming-connections)
    * [允许 Established Outgoing Connections](#允许-established-outgoing-connections)
    * [把eth1 的流量转到 eth0](#把eth1-的流量转到-eth0)
    * [丢掉 Invalid Packets](#丢掉-invalid-packets)
    * [丢弃某个ip的流量](#丢弃某个ip的流量)
    * [reject某个ip（reject 和drop的不同，reject会发rst包，drop只能等超时了）](#reject某个ipreject-和drop的不同reject会发rst包drop只能等 超时了)
    * [丢掉一个网卡所有流量](#丢掉一个网卡所有流量)
    * [允许所有的ssh端口（22端口）](#允许所有的ssh端口22端口)
    * [允许来自某个ip或者子网的 Incoming SSH 连接](#允许来自某个ip或者子网的-incoming-ssh-连接)
    * [放行ssh出方向](#放行ssh出方向)
    * [允许来自某个ip或者子网的 rsync 端口](#允许来自某个ip或者子网的-rsync-端口)
    * [放行所有80端口入方向](#放行所有80端口入方向)
    * [放行所有https](#放行所有https)
    * [放行80 和 443](#放行80-和-443)
    * [放行 mysql 3306](#放行-mysql-3306)
    * [放行 eth1的mysql](#放行-eth1的mysql)
    * [放行PostgreSQL](#放行postgresql)
    * [放行 eth1的PostgreSQL](#放行-eth1的postgresql)
    * [block 25端口出](#block-25端口出)
    * [放行25端口 入](#放行25端口-入)
    * [放行所有的IMAP](#放行所有的imap)
    * [放行所有的IAMPS](#放行所有的iamps)
    * [放行所有的pop3](#放行所有的pop3)
    * [放行所有的pop3s](#放行所有的pop3s)
    * [丢掉所有在外网网卡上出现的私有网流量（不应该出现）](#丢掉所有在外网网卡上出现的私有网流量不应该出现)
    * [丢掉所有的出方向 facebook 流量（基于域名）](#丢掉所有的出方向-facebook-流量基于域名)
    * [对丢包的流量打log审计](#对丢包的流量打log审计)
    * [对丢包审计，限制日志大小](#对丢包审计限制日志大小)
    * [针对mac地址的放行、丢包策略](#针对mac地址的放行丢包策略)
    * [针对icmp协议的放行、丢包策略](#针对icmp协议的放行丢包策略)
    * [一次处理多个ports](#一次处理多个ports)
    * [使用random 或者 nth* 进行负载均衡策略](#使用random-或者-nth-进行负载均衡策略)
    * [限制连接数](#限制连接数)
    * [Maintaining a List of recent Connections to Match Against](#maintaining-a-list-of-recent-connections-to-match-against)
    * [Matching Against a string* in a Packet's Data Payload](#matching-against-a-string-in-a-packets-data-payload)
    * [基于时间规则](#基于时间规则)
    * [Packet Matching Based on TTL Values](#packet-matching-based-on-ttl-values)
    * [防止有人在烧端口](#防止有人在烧端口)
    * [ssh防暴力破解](#ssh防暴力破解)
    * [防止 syn flood 攻击](#防止-syn-flood-攻击)
       * [Mitigating SYN Floods With SYNPROXY](#mitigating-syn-floods-with-synproxy)
    * [干掉不是通过syn包建立的tcp](#干掉不是通过syn包建立的tcp)
    * [Force Fragments packets check](#force-fragments-packets-check)
    * [XMAS packets](#xmas-packets)
    * [Drop all NULL packets](#drop-all-null-packets)
    * [Block Uncommon MSS Values](#block-uncommon-mss-values)
    * [Block Packets With Bogus TCP Flags](#block-packets-with-bogus-tcp-flags)
    * [Block Packets From Private Subnets (Spoofing)](#block-packets-from-private-subnets-spoofing)

****

### Tools to help you configure Iptables

<p>
&nbsp;&nbsp;:small_orange_diamond: <a href="http://shorewall.org/"><b>Shorewall</b></a> - advanced gateway/firewall configuration tool for GNU/Linux.<br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://firewalld.org/"><b>Firewalld</b></a> - provides a dynamically managed firewall.<br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://wiki.ubuntu.com/UncomplicatedFirewall"><b>UFW</b></a> - default firewall configuration tool for Ubuntu.<br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://github.com/firehol/firehol"><b>FireHOL</b></a> - offer simple and powerful configuration for all Linux firewall and traffic shaping requirements.<br>
</p>

### Manuals/Howtos/Tutorials

<p>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://major.io/2010/04/12/best-practices-iptables/"><b>Best practices: iptables - by Major Hayden</b></a><br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://www.booleanworld.com/depth-guide-iptables-linux-firewall/"><b>An In-Depth Guide to Iptables, the Linux Firewall</b></a><br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://linuxgazette.net/108/odonovan.html"><b>Advanced Features of netfilter/iptables</b></a><br>
&nbsp;&nbsp;:small_orange_diamond: <a href="http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables"><b>Linux Firewalls Using iptables</b></a><br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://serverfault.com/questions/696182/debugging-iptables-and-common-firewall-pitfalls"><b>Debugging iptables and common firewall pitfalls?</b></a><br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-4.html"><b>Netfilter Hacking HOWTO</b></a><br>
&nbsp;&nbsp;:small_orange_diamond: <a href="https://making.pusher.com/per-ip-rate-limiting-with-iptables/"><b>Per-IP rate limiting with iptables</b></a><br>
</p>

### How it works?

<p align="center">
    <img src="https://github.com/trimstray/iptables-essentials/blob/master/doc/img/iptables-packet-flow-ng.png"
        alt="Master">
</p>

### Iptables Rules

#### 保存规则 

save rules

###### Debian Based

```bash
netfilter-persistent save
```

###### RedHat Based

```bash
service iptables save
```

#### 列出所有规则（verbose）

List out all of the active iptables rules with verbose

```bash
iptables -n -L -v
```

#### 列出所有规则，带行号 

List out all of the active iptables rules with numeric lines and verbose

```bash
iptables -n -L -v --line-numbers
```

#### 列出所有active规则

Print out all of the active iptables rules

```bash
iptables -S
```

#### 列出所有 INPUT chain 规则（表格形式）

List Rules as Tables for INPUT chain

```bash
iptables -L INPUT
```

#### 列出 INPUT chain 详情

Print all of the rule specifications in the INPUT chain

```bash
iptables -S INPUT
```

#### 列出packet个数，大小等信息

Show Packet Counts and Aggregate Size

```bash
iptables -L INPUT -v
```

####  列出 INPUT，OUTPUT 规则，带行号

To display INPUT or OUTPUT chain rules with numeric lines and verbose

```bash
iptables -L INPUT -n -v
iptables -L OUTPUT -n -v --line-numbers
```

####  删除规则（通过行号）

Delete Rule by Chain and Number

```bash
iptables -D INPUT 10
```

####  删除规则（通过详情）

Delete Rule by Specification

```bash
iptables -D INPUT -m conntrack --ctstate INVALID -j DROP
```

####  清空所有规则（！）

Flush All Rules, Delete All Chains, and Accept All

```bash
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X
```

####  清空所有chains

Flush All Chains

```bash
iptables -F
```

####  清空单个chain

Flush a Single Chain

```bash
iptables -F INPUT
```

####  加入一条规则

Insert Firewall Rules

```bash
iptables -I INPUT 2 -s 202.54.1.2 -j DROP
```

####  允许 loopback 连接

Allow Loopback Connections

```bash
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
```

####  允许 Established and Related Incoming Connections 

Allow Established and Related Incoming Connections

```bash
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

####  允许 Established Outgoing Connections

Allow Established Outgoing Connections

```bash
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

####  把eth1 的流量转到 eth0

Internal to External

```bash
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
```

#### 丢掉 Invalid Packets


Drop Invalid Packets

```bash
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
```

####  丢弃某个ip的流量

Block an IP Address

```bash
iptables -A INPUT -s 192.168.252.10 -j DROP
```

####  reject某个ip（reject 和drop的不同，reject会发rst包，drop只能等超时了）

Block and IP Address and Reject

```bash
iptables -A INPUT -s 192.168.252.10 -j REJECT
```

####  丢掉一个网卡所有流量 

Block Connections to a Network Interface

```bash
iptables -A INPUT -i eth0 -s 192.168.252.10 -j DROP
```

####  允许所有的ssh端口（22端口）

Allow All Incoming SSH

```bash
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 允许来自某个ip或者子网的 Incoming SSH 连接

Allow Incoming SSH from Specific IP address or subnet

```bash
iptables -A INPUT -p tcp -s 192.168.240.0/24 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行ssh出方向

Allow Outgoing SSH

```bash
iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

####   允许来自某个ip或者子网的 rsync 端口

Allow Incoming Rsync from Specific IP Address or Subnet

```bash
iptables -A INPUT -p tcp -s 192.168.240.0/24 --dport 873 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 873 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行所有80端口入方向

Allow All Incoming HTTP

```bash
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行所有https

Allow All Incoming HTTPS

```bash
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行80 和 443

Allow All Incoming HTTP and HTTPS

```bash
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行 mysql 3306

Allow MySQL from Specific IP Address or Subnet

```bash
iptables -A INPUT -p tcp -s 192.168.240.0/24 --dport 3306 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行 eth1的mysql

Allow MySQL to Specific Network Interface

```bash
iptables -A INPUT -i eth1 -p tcp --dport 3306 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth1 -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行PostgreSQL 

PostgreSQL from Specific IP Address or Subnet

```bash
iptables -A INPUT -p tcp -s 192.168.240.0/24 --dport 5432 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 5432 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

####  放行 eth1的PostgreSQL

Allow PostgreSQL to Specific Network Interface

```bash
iptables -A INPUT -i eth1 -p tcp --dport 5432 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth1 -p tcp --sport 5432 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### block 25端口出

Block Outgoing SMTP Mail

```bash
iptables -A OUTPUT -p tcp --dport 25 -j REJECT
```

####  放行25端口 入

Allow All Incoming SMTP

```bash
iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行所有的IMAP

Allow All Incoming IMAP

```bash
iptables -A INPUT -p tcp --dport 143 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 143 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行所有的IAMPS

Allow All Incoming IMAPS

```bash
iptables -A INPUT -p tcp --dport 993 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 993 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

#### 放行所有的pop3

Allow All Incoming POP3

```bash
iptables -A INPUT -p tcp --dport 110 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 110 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

####  放行所有的pop3s

Allow All Incoming POP3S

```bash
iptables -A INPUT -p tcp --dport 995 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 995 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

####  丢掉所有在外网网卡上出现的私有网流量（不应该出现）

Drop Private Network Address On Public Interface

```bash
iptables -A INPUT -i eth1 -s 192.168.0.0/24 -j DROP
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP
```

#### 丢掉所有的出方向 facebook 流量（基于域名）

Drop All Outgoing to Facebook Networks

Get Facebook AS:

```bash
whois -h v4.whois.cymru.com " -v $(host facebook.com | grep "has address" | cut -d " " -f4)" | tail -n1 | awk '{print $1}'
```

Drop:

```bash
for i in $(whois -h whois.radb.net -- '-i origin AS32934' | grep "^route:" | cut -d ":" -f2 | sed -e 's/^[ \t]*//' | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | cut -d ":" -f2 | sed 's/$/;/') ; do

  iptables -A OUTPUT -s "$i" -j REJECT

done
```

#### 对丢包的流量打log审计

Log and Drop Packets

```bash
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j LOG --log-prefix "IP_SPOOF A: "
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP
```

By default everything is logged to `/var/log/messages` file:

```bash
tail -f /var/log/messages
grep --color 'IP SPOOF' /var/log/messages
```

#### 对丢包审计，限制日志大小

Log and Drop Packets with Limited Number of Log Entries

```bash
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix "IP_SPOOF A: "
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP
```

####  针对mac地址的放行、丢包策略

Drop or Accept Traffic From Mac Address

```bash
iptables -A INPUT -m mac --mac-source 00:0F:EA:91:04:08 -j DROP
iptables -A INPUT -p tcp --destination-port 22 -m mac --mac-source 00:0F:EA:91:04:07 -j ACCEPT
```

####  针对icmp协议的放行、丢包策略

Block or Allow ICMP Ping Request

```bash
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -A INPUT -i eth1 -p icmp --icmp-type echo-request -j DROP
```

#### 一次处理多个ports

Specifying Multiple Ports with `multiport`

```bash
iptables -A INPUT -i eth0 -p tcp -m state --state NEW -m multiport --dports ssh,smtp,http,https -j ACCEPT
```

####  使用random 或者 nth* 进行负载均衡策略

Load Balancing with `random*` or `nth*`

```bash
_ips=("172.31.250.10" "172.31.250.11" "172.31.250.12" "172.31.250.13")

for ip in "${_ips[@]}" ; do
  iptables -A PREROUTING -i eth0 -p tcp --dport 80 -m state --state NEW -m nth --counter 0 --every 4 --packet 0 \
    -j DNAT --to-destination ${ip}:80
done
```

or

```bash
_ips=("172.31.250.10" "172.31.250.11" "172.31.250.12" "172.31.250.13")

for ip in "${_ips[@]}" ; do
  iptables -A PREROUTING -i eth0 -p tcp --dport 80 -m state --state NEW -m random --average 25 \
    -j DNAT --to-destination ${ip}:80
done
```

#### 限制连接数

Restricting the Number of Connections with `limit` and `iplimit*`

```bash
iptables -A FORWARD -m state --state NEW -p tcp -m multiport --dport http,https -o eth0 -i eth1 \
    -m limit --limit 20/hour --limit-burst 5 -j ACCEPT
```

or

```bash
iptables -A INPUT -p tcp -m state --state NEW --dport http -m iplimit --iplimit-above 5 -j DROP
```

#### Maintaining a List of recent Connections to Match Against



```bash
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 100 -j DROP
iptables -A FORWARD -p tcp -i eth0 --dport 443 -m recent --name portscan --set -j DROP
```

####  Matching Against a `string*` in a Packet's Data Payload



```bash
iptables -A FORWARD -m string --string '.com' -j DROP
iptables -A FORWARD -m string --string '.exe' -j DROP
```

####  基于时间规则 

Time-based Rules with `time*`

```bash
iptables -A FORWARD -p tcp -m multiport --dport http,https -o eth0 -i eth1 \
    -m time --timestart 21:30 --timestop 22:30 --days Mon,Tue,Wed,Thu,Fri -j ACCEPT
```

#### Packet Matching Based on TTL Values

```bash
iptables -A INPUT -s 1.2.3.4 -m ttl --ttl-lt 40 -j REJECT
```

#### 防止有人在烧端口

Protection against port scanning

```bash
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP
```

#### ssh防暴力破解

SSH brute-force protection

```bash
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
```

#### 防止 syn flood 攻击

Syn-flood protection

```bash
iptables -N syn_flood

iptables -A INPUT -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn_flood -j DROP

iptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT

iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
iptables -A INPUT -p icmp -j DROP

iptables -A OUTPUT -p icmp -j ACCEPT
```

##### Mitigating SYN Floods With SYNPROXY

```bash
iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
```

#### 干掉不是通过syn包建立的tcp

Block New Packets That Are Not SYN

```bash
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
```

or

```bash
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
```

#### Force Fragments packets check

```bash
iptables -A INPUT -f -j DROP
```

#### XMAS packets

```bash
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
```

#### Drop all NULL packets

```bash
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
```

#### Block Uncommon MSS Values

```bash
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
```

#### Block Packets With Bogus TCP Flags

```bash
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
```

#### Block Packets From Private Subnets (Spoofing)

```bash
_subnets=("224.0.0.0/3" "169.254.0.0/16" "172.16.0.0/12" "192.0.2.0/24" "192.168.0.0/16" "10.0.0.0/8" "0.0.0.0/8" "240.0.0.0/5")

for _sub in "${_subnets[@]}" ; do
  iptables -t mangle -A PREROUTING -s "$_sub" -j DROP
done
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
```
