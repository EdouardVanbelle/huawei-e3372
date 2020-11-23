# Huawei E3372 API wrapper

Current focus: sms API

Inspired from: https://github.com/arska/e3372


# Command line help

$ ./huawei.py --help
```
usage: huawei.py [-h] [--host HOST] [--verbose] [--output {human,bash,json}]
                 {device,monitoring,net,modem,sms,api} ...

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           IP address to query (default: 192.168.8.1)
  --verbose, -v         verbose mode
  --output {human,bash,json}, -o {human,bash,json}
                        output format (default: human)

section command:
  {device,monitoring,net,modem,sms,api}
                        section name
    device              device operations (--help for details)
    monitoring          monitoring operation (--help for details)
    net                 net operation (--help for details)
    modem               modem actions (--help for details)
    sms                 sms actions (--help for details)
    api                 helper call directly API
```

$ ./huawei.py device --help
```
usage: huawei.py device [-h] {information,signal,reboot}

positional arguments:
  {information,signal,reboot}
                        information

optional arguments:
  -h, --help            show this help message and exit
```

# read device information

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

$ ./huawei.py sms send --phone '+33...' --message 'Hello you !'
```
OK
```


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

$ ./huawei.py sms mack --id 40023
```
OK
```

$ ./huawei.py sms mdel --id 40004
```
OK
```

# modem sample (network connectivity)

$ ./huawei.py modem status
```
False
```

$ ./huawei.py modem on
```
OK
```

$ ./huawei.py modem status
```
True
```

