# Huawei E3372 API wrapper

This is a wrapper to handle E3372 devices

Tested device: E3372h-320 (with software version 10.0.3.1)

Code inspired from: https://github.com/arska/e3372

## API 
Sample of use:

```python
import pprint
import huawei.hilink

# connect to device
e3372 = huawei.hilink.HuaweiE3372()

session=None

if e3372.user_login_required():
    # ok device is expecting login
    session=e3372.login( 'admin', 'my pretty password')
 
print "Device phone number: "+e3372.device_information().get("Msisdn");
print "Unread messages: "+e3372.monitoring_check_notifications().get("UnreadMessage")
print "Total contacts: {count}".format( count = e3372.sms_count_contact())

# send a sms
e3372.send_sms( '+33....', 'Hello world')

# ...

# do not forget to cleanup session on server side (opened sessions are limited)
if session != None:
    e3372.user_logout()

```


## CLI tool

### help

$ ./huawei.py --help
```
usage: huawei.py [-h] [--host HOST] [-v] [-p PASSWORD] [-u USER]
                 [-o {flat,json}]
                 {device,monitoring,net,modem,sms,api} ...

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           IP address to query (default: 192.168.8.1)
  -v, --verbose         verbose mode
  -p PASSWORD, --password PASSWORD
                        password for login
  -u USER, --user USER  user for login (default: admin)
  -o {flat,json}, --output {flat,json}
                        output format (default: flat)

section command (--help for specific details):
  {device,monitoring,net,modem,sms,api}
    device              device operations
    monitoring          monitoring operation
    net                 net operations
    modem               modem operations
    sms                 sms operations
    api                 helper, direct API call (GET only)
```

$ ./huawei.py sms --help
```
usage: huawei.py sms [-h]
                     {status,send,browse,list,contact,list-by-phone,ack-message,del-message,del-contact}
                     ...

optional arguments:
  -h, --help            show this help message and exit

section command:
  {status,send,browse,list,contact,list-by-phone,ack-message,del-message,del-contact}
                        action name
    status              sms status (informations)
    send                send sms
    browse              browse contacts and messages
    list                list message in a given box
    contact             get contacts and their last message
    list-by-phone       list message for a given contact (phone)
    ack-message         acknowledge a message
    del-message         delete a message
    del-contact         delete a contact (and associated messages)
```

$ ./huawei.py sms list --help
```
usage: huawei.py sms list [-h] [--box BOX]

optional arguments:
  -h, --help  show this help message and exit
  --box BOX   1:local-inbox 2:local-sent 3:local-draft 4:local-trash 5:sim-
              inbox 6:sim-sent 7:sim-draft 8:sim-trash
```

### when password is required

$ ./huawei.py  monitoring notifications

```
Password is expected, please add --password in parameters
```

$ ./huawei.py  --password '...' monitoring notifications

```
Logging in...
UnreadMessage: 0
SmsStorageFull: 0
OnlineUpdateStatus: 13
SimOperEvent: 0
Logging out...
OK
```

### read device information

$ ./huawei.py device information
```
DeviceName: E3372h-320
SerialNumber: VQND.....
Imei: 8......
Imsi: 2.....
Iccid: 8.....
Msisdn: +33......
HardwareVersion: CL4E3372HM
SoftwareVersion: 10.0.3.1(H192SP1C983)
WebUIVersion: WEBUI 10.0.3.1(W13SP2C7110)
MacAddress1: 00:10:......
MacAddress2: None
WanIPAddress: 10.147.223.227
wan_dns_address: 212.27.40.240,212.27.40.241
WanIPv6Address: None
wan_ipv6_dns_address: None
ProductFamily: LTE
Classify: hilink
supportmode: LTE|WCDMA|GSM
workmode: LTE
submask: 255.255.255.255
Mccmnc: 20815
iniversion: E3372h-320-CUST 10.0.3.2(C1217)
uptime: 141515
ImeiSvn: 05
spreadname_en: None
spreadname_zh: None
```

Send a message to +33...

$ ./huawei.py sms send --phone '+33...' --message 'Hello you !'
```
OK
```

Send a message to multiple recipient

$ ./huawei.py sms send --phone "+3361....; +3368...." --message 'message multiple 2 !'
```
OK
```

Get all contacts and messages

$ ./huawei.py sms browse
```
Device phone number: +337...
Unread messages: 1
Total conversations: 4

Conversation with +3361.... (msg: 37)
  40002 < 2020-11-22 01:20:36 Exemple d'un message très long donc qui prend plus d'un seul SMS, le but est de voir le résultat au sein de l'application Huawei. J'espère que ça fonctionnera bien...
  40003 < 2020-11-22 01:24:28 None
  40007 > 2020-11-22 12:53:36 Hello you !
  40008 > 2020-11-22 12:57:28 Hello you !
  40009 < 2020-11-22 12:58:00 Top
  40000 < 2020-11-22 13:27:43 A table
  40010 > 2020-11-22 14:59:10 Hello you ça marche éhéhé !
  40011 > 2020-11-22 15:00:39 test nouveau message
  40012 > 2020-11-22 15:02:11 Hello you ça marche éhéhé !
  40013 > 2020-11-22 15:04:06 Hello you ! ça marche éhéhé صباح الخير ! 
  40014 < 2020-11-22 15:04:29 None
  40015 > 2020-11-22 15:04:32 Hello you ! ça marche éhéhé صباح الخير ! 
  40016 < 2020-11-22 15:05:11 Test    !
  40001 > 2020-11-22 15:17:17 Hello you ça marche éhéhé !
  40018 < 2020-11-22 15:26:28 Purge
  40020 < 2020-11-22 16:30:02 Ok
  40021 < 2020-11-22 16:31:03 Ok 2
  40022 < 2020-11-22 16:31:44 Ça marche plus
  40024 < 2020-11-22 18:12:37 Encore
  40025 > 2020-11-23 12:21:40 Hello you ! ça marche éhéhé ! صباح الخير 
  40026 < 2020-11-23 12:22:14 Oui !
  40017 > 2020-11-23 16:05:58 Hello you !
  40023 < 2020-11-23 16:13:10 Plop
  40004 > 2020-11-24 01:11:25 got to sleep
  40006 > 2020-11-25 12:08:07 hééééé, ça marche super !
  40027 > 2020-11-25 12:08:15 hééééé, ça marche super !
  40028 < 2020-11-25 12:29:08 New message
  40029 < 2020-11-25 12:40:23 New 2
  40030 < 2020-11-25 12:46:18 Yop
  40031 < 2020-11-25 12:51:03 Yop 2
  40032 < 2020-11-25 12:51:15 Enfin !
  40033 < 2020-11-25 12:55:21 Yeee
  40034 < 2020-11-25 13:00:03 Test
  40035 > 2020-11-25 16:21:23 hééééé, ça marche super yop !
  40037 < 2020-11-25 18:40:04 Ok
  40036 > 2020-11-26 18:20:13 ééé ça marche !
  40039 N 2020-11-26 18:42:08 Plop

Conversation with +3361...;+3368... (msg: 1)
  40038 > 2020-11-26 18:40:43 message multiple !

Conversation with +3371... (msg: 1)
  40019 > 2020-11-21 21:49:40 j'arrive!

Conversation with Free Mobile (msg: 1)
  40005 < 2020-11-20 11:13:48 INFO FREE : nos boutiques sont ouvertes et vous accueillent en toute sécurité. Pour éviter l'attente, prenez rendez-vous en ligne avec l'un de nos conseillers ! Plus d'infos ou prendre RDV sur bit.ly/Boutiques-Free .

```

Acknowledge a message

$ ./huawei.py sms ack-message --id 40023
```
OK
```

Delete a message

$ ./huawei.py sms del-message --id 40004
```
OK
```

### modem sample (network connectivity)

Is internet active (Data) ?

$ ./huawei.py modem status
```
False
```

Activate data 

$ ./huawei.py modem on
```
OK
```

Is internet active (Data) ?

$ ./huawei.py modem status
```
True
```

### request a direct API call (GET with a specified path)

$ ./huawei.py api --path dhcp/settings
```
DnsStatus: 1
DhcpStartIPAddress: 192.168.8.100
DhcpIPAddress: 192.168.8.1
accessipaddress: None
homeurl: hi.link
DhcpStatus: 1
DhcpLanNetmask: 255.255.255.0
SecondaryDns: 192.168.8.1
PrimaryDns: 192.168.8.1
DhcpEndIPAddress: 192.168.8.200
DhcpLeaseTime: 86400
```


