# Huawei E3372 API wrapper

Inspired from: https://github.com/arska/e3372

## API 
Sample of use:

```python
import pprint
import huawei.hilink

e3372 = huawei.hilink.HuaweiE3372()
print "device phone number: "+e3372.device_information().get("Msisdn");
print "Unread messages: "+e3372.monitoring_check_notifications().get("UnreadMessage")
print "Total contacts: {count}".format( count = e3372.sms_count_contact())

# send a sms
e3372.send_sms( '+33....', 'Hello world')

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
device phone number: +33...
Unread messages: 1
Total contacts: 3

Contact +33... (msg: 24)
Message #40002 incoming [r] with +33... at 2020-11-22 01:20:36 (SmsStatus.ReceivedSeen SmsType.Aggregated): Exemple d'un message très long donc qui prend plus d'un seul SMS, le but est de voir le résultat au sein de l'application Huawei. J'espère que ça fonctionnera bien...
Message #40003 incoming [r] with +33... at 2020-11-22 01:24:28 (SmsStatus.ReceivedSeen SmsType.MMS5): None
Message #40004 outgoing [-] with +33... at 2020-11-22 12:49:43 (SmsStatus.SentOk SmsType.Simple): Hello you !
Message #40006 outgoing [-] with +33... at 2020-11-22 12:53:29 (SmsStatus.SentOk SmsType.Simple): Hello you !
Message #40007 outgoing [-] with +33... at 2020-11-22 12:53:36 (SmsStatus.SentOk SmsType.Simple): Hello you !
Message #40008 outgoing [-] with +33... at 2020-11-22 12:57:28 (SmsStatus.SentOk SmsType.Simple): Hello you !
Message #40009 incoming [r] with +33... at 2020-11-22 12:58:00 (SmsStatus.ReceivedSeen SmsType.Simple): Top
Message #40000 incoming [r] with +33... at 2020-11-22 13:27:43 (SmsStatus.ReceivedSeen SmsType.Simple): A table
Message #40010 outgoing [-] with +33... at 2020-11-22 14:59:10 (SmsStatus.SentOk SmsType.Simple): Hello you ça marche éhéhé !
Message #40011 outgoing [-] with +33... at 2020-11-22 15:00:39 (SmsStatus.SentOk SmsType.Simple): test nouveau message
Message #40012 outgoing [-] with +33... at 2020-11-22 15:02:11 (SmsStatus.SentOk SmsType.Simple): Hello you ça marche éhéhé !
Message #40013 outgoing [-] with +33... at 2020-11-22 15:04:06 (SmsStatus.SentOk SmsType.Simple): Hello you ! ça marche éhéhé صباح الخير ! 
Message #40014 incoming [r] with +33... at 2020-11-22 15:04:29 (SmsStatus.ReceivedSeen SmsType.Simple): None
Message #40015 outgoing [-] with +33... at 2020-11-22 15:04:32 (SmsStatus.SentOk SmsType.Simple): Hello you ! ça marche éhéhé صباح الخير ! 
Message #40016 incoming [r] with +33... at 2020-11-22 15:05:11 (SmsStatus.ReceivedSeen SmsType.Simple): Test    !
Message #40001 outgoing [-] with +33... at 2020-11-22 15:17:17 (SmsStatus.SentOk SmsType.Simple): Hello you ça marche éhéhé !
Message #40018 incoming [r] with +33... at 2020-11-22 15:26:28 (SmsStatus.ReceivedSeen SmsType.Simple): Purge
Message #40020 incoming [r] with +33... at 2020-11-22 16:30:02 (SmsStatus.ReceivedSeen SmsType.Simple): Ok
Message #40021 incoming [r] with +33... at 2020-11-22 16:31:03 (SmsStatus.ReceivedSeen SmsType.Simple): Ok 2
Message #40022 incoming [r] with +33... at 2020-11-22 16:31:44 (SmsStatus.ReceivedSeen SmsType.Simple): Ça marche plus
Message #40024 incoming [r] with +33... at 2020-11-22 18:12:37 (SmsStatus.ReceivedSeen SmsType.Simple): Encore
Message #40025 outgoing [-] with +33... at 2020-11-23 12:21:40 (SmsStatus.SentOk SmsType.Simple): Hello you ! ça marche éhéhé ! صباح الخير 
Message #40026 incoming [r] with +33... at 2020-11-23 12:22:14 (SmsStatus.ReceivedSeen SmsType.Simple): Oui !
Message #40023 incoming [N] with +33... at 2020-11-23 16:13:10 (SmsStatus.ReceivedUnseen SmsType.Simple): Plop

Contact +33... (msg: 1)
Message #40019 outgoing [-] with +336... at 2020-11-21 21:49:40 (SmsStatus.SentOk SmsType.Simple): j'arrive!

Contact Free Mobile (msg: 1)
Message #40005 incoming [r] with Free Mobile at 2020-11-20 11:13:48 (SmsStatus.ReceivedSeen SmsType.Aggregated): INFO FREE : nos boutiques sont ouvertes et vous accueillent en toute sécurité. Pour éviter l'attente, prenez rendez-vous en ligne avec l'un de nos conseillers ! Plus d'infos ou prendre RDV sur bit.ly/Boutiques-Free .
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


