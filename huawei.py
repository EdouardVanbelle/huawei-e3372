#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :

import sys
import pprint
import requests
import xmltodict
from xml.sax.saxutils import escape
from datetime import datetime

'''
Try Reverse Eng:

    smstat:
        4 errorSent
        3 sent
        2 draft
        1 received
        0 unread

    curbox:
        0 incoming
        1 outgoing

    savetype:
        3 sent
        0 received

    smstype
        1 simple (less than 160 chars)
        2 aggregated (more than 160 chars)
        4 5 6: multiusers (MMS: case not managed by this device)
        7: smsreport (success) ? ?
        8: smsreport (failed)
        9: alert ?
        10: info ?

     ConnectionStatus:
       900: connecting
       901: connected
       902: disconnected
       903: disconnecting
       ...

'''

class HuaweiE3372(object):
    BASE_URL = 'http://{host}'
    COOKIE_URL = '/html/index.html'

    # all unmapped APIs
    # details also available on: https://blog.hqcodeshop.fi/archives/259-Huawei-E5186-AJAX-API.html
    XML_APIS = [
        '/api/device/basic_information',
        '/api/monitoring/status',
        '/api/global/module-switch',
        '/api/net/net-mode',
    ]
    session = None

    def __init__(self, host='192.168.8.1'):
        self.host = host
        self.base_url = self.BASE_URL.format(host=host)
        self.session = requests.Session()
        self.tokens = []
        self.__device_information = None
        # get a session cookie by requesting the COOKIE_URL
        r = self.session.get(self.base_url + self.COOKIE_URL)

    def __api_decode( self, response):
        '''helper to decode answer from API
        '''

        # FIXME: is response.raise_for_status() better ?
        if not response.ok:
            raise Exception( response)

        # check additional token in answer
        if '__RequestVerificationToken' in response.headers:
            self.tokens.append( response.headers['__RequestVerificationToken'])
            #DEBUG print "additional token "+response.headers['__RequestVerificationToken']

        # Don't check content-type as it is always a text/html event for pure XML answer
        # print "content: "+response.headers.get('content-type')

        xml = response.text

        # ensure we have a XML answer
        if not xml.startswith( "<?xml", 0, 5):
            raise Exception( "This is not a XML answer")

        data = xmltodict.parse( xml)

        if "error" in data:
            code    = int( data['error']['code'])
            message = data['error']['message']

            if code == 100010:
                #FIXME should use better exception
                raise FileNotFoundError()
            elif code == 100005:
                #FIXME should use correct exception
                raise Exception( code, "missing argument")
            else:
                # unknown case
                raise Exception( code, message)

        if not "response" in data:
            raise Exception("parse exception")

        '''
        format: 
        <error>
        <code>113055</code>
        <message></message>
        </error>
        '''

        return data.get("response", None)

    def __get(self, path):

        #DEBUG print "GET "+self.base_url + path

        return self.__api_decode( self.session.get( self.base_url + path))

    def __get_token(self):
        data=self.__get( "/api/webserver/token")

        #FIXME better notation ?
        token = data.get('token', None);

        #DEBUG print "TOKEN "+token

        #DEBUG print "got token "+token
        self.tokens.append( token);

    def __post( self, path, payload):

        # get token only if necessary
        if len( self.tokens) == 0:
            self.__get_token()

        token = self.tokens.pop()

        #DEBUG print "using token "+token
        #DEBUG print "sending : "+payload

        # XXX: do we need to force content ? Content-Type: application/x-www-form-urlencoded; charset=UTF-8;
        return self.__api_decode( self.session.request( 
            'POST', 
            self.base_url + path,
            headers = { '__RequestVerificationToken' : token },
            data = payload
        ))

    def device_information( self):
        '''get device information

        return hash with keys: 
            'DeviceName', 'E3372h-320' 
            'SerialNumber', ...
            'Imei', ...
            'Imsi', ...
            'Iccid', ...
            'Msisdn', ...  # aka phone number
            'HardwareVersion', 'CL4E3372HM', 
            'SoftwareVersion', '10.0.3.1(H192SP1C983', 
            'WebUIVersion', 'WEBUI 10.0.3.1(W13SP2C7110', 
            'MacAddress1', ....
            'MacAddress2', None, 
            'WanIPAddress', ...
            'wan_dns_address', ... (coma separated)
            'WanIPv6Address', None, 
            'wan_ipv6_dns_address', None, 
            'ProductFamily', 'LTE', 
            'Classify', 'hilink', 
            'supportmode', 'LTE|WCDMA|GSM', 
            'workmode', 'LTE', 
            'submask', '255.255.255.255', 
            'Mccmnc', '20815', 
            'iniversion', 'E3372h-320-CUST 10.0.3.2(C1217', 
            'uptime', '476914'  # in second 
            'ImeiSvn', '05', 
            'spreadname_en', None, 
            'spreadname_zh', None
        '''

        # cache data
        if self.__device_information == None:
            self.__device_information = self.__get('/api/device/information')

        return self.__device_information

    def device_signal( self):
        ''' get device signal info

            explainations:
                https://wiki.teltonika-networks.com/view/Mobile_Signal_Strength_Recommendations

            RSSI:
                regarding RSSI for 4G
                > -65 dBm	Excellent	Strong signal with maximum data speeds
                -65 dBm to -75 dBm	Good	Strong signal with good data speeds
                -75 dBm to -85 dBm	Fair	Fair but useful, fast and reliable data speeds may be attained, but marginal data with drop-outs is possible
                -85 dBm to -95 dBm	Poor	Performance will drop drastically
                <= -95 dBm	No signal	Disconnection

                more info: https://wiki.teltonika-networks.com/view/RSSI

            return values:
                ('pci', u'1')
                ('sc', None)
                ('cell_id', u'.....')
                ('rsrq', u'-13.0dB')
                ('rsrp', u'-106dBm')
                ('rssi', u'-75dBm')
                ('sinr', u'6dB')
                ('rscp', None)
                ('ecio', None)
                ('mode', u'7')
                ('ulbandwidth', u'15MHz')
                ('dlbandwidth', u'15MHz')
                ('txpower', u'PPusch:22dBm PPucch:11dBm PSrs:22dBm PPrach:17dBm')
                ('tdd', None)
                ('ul_mcs', u'mcsUpCarrier1:6')
                ('dl_mcs', u'mcsDownCarrier1Code0:1 mcsDownCarrier1Code1:0')
                ('earfcn', u'DL:1675 UL:19675')
                ('rrc_status', None)
                ('rac', None)
                ('lac', None)
                ('tac', u'5902')
                ('band', u'3')
                ('nei_cellid', u'No1:1No2:62')
                ('plmn', u'20815')
                ('ims', None)
                ('wdlfreq', None)
                ('lteulfreq', u'17575')
                ('ltedlfreq', u'18525')
                ('transmode', None)
                ('enodeb_id', u'0407729')
                ('cqi0', u'32639')
                ('cqi1', u'32639')
                ('ulfrequency', u'1757500kHz')
                ('dlfrequency', u'1852500kHz')
                ('arfcn', None)
                ('bsic', None)
                ('rxlev', None)])

        '''
        return self.__get('/api/device/signal')

    def traffic_statistics( self):
        '''return statistics

        values:
            (u'CurrentConnectTime', u'2174')
            (u'CurrentUpload', u'390')
            (u'CurrentDownload', u'255')
            (u'CurrentDownloadRate', u'0')
            (u'CurrentUploadRate', u'0')
            (u'TotalUpload', u'1800371')
            (u'TotalDownload', u'687051')
            (u'TotalConnectTime', u'612412')
            (u'showtraffic', u'1')
        '''

        return self.__get( "/api/monitoring/traffic-statistics")

    def get_provider( self):
        ''' get provider name

        return:
            (u'State', u'0')
            (u'FullName', u'...')
            (u'ShortName', u'...')
            (u'Numeric', u'...')
            (u'Rat', u'7')
            (u'Spn', None)
        '''
        return self.__get('/api/net/current-plmn');

    def get_phone( self):
        return self.device_information().get('Msisdn')

    def get(self, path):
        return self.__get( path)

    def check_notifications( self):
        '''Check for notifications

        return: {
            unreadMessage: <int>,
            smsStorageFull: <boolean>
        }

        Debug:
        <?xml version="1.0" encoding="UTF-8"?>
        <response>
        <UnreadMessage>1</UnreadMessage>
        <SmsStorageFull>0</SmsStorageFull>
        <OnlineUpdateStatus>13</OnlineUpdateStatus>
        <SimOperEvent>0</SimOperEvent>
        </response>
        '''

        data = self.__get( '/api/monitoring/check-notifications')

        return {
            "unreadMessage": int( data.get("UnreadMessage", None)),
            "smsStorageFull": (data.get("SmsStorageFull", None)== "1")
        }



    def sms_count( self):
        '''Sms count

        Debug:
        <?xml version="1.0" encoding="utf-8"?>
        <response>
                <LocalUnread>1</LocalUnread>
                <LocalInbox>4</LocalInbox>
                <LocalOutbox>11</LocalOutbox>
                <LocalDraft>0</LocalDraft>
                <LocalDeleted>0</LocalDeleted>
                <SimUnread>0</SimUnread>
                <SimInbox>0</SimInbox>
                <SimOutbox>0</SimOutbox>
                <SimDraft>0</SimDraft>
                <LocalMax>500</LocalMax>
                <SimMax>100</SimMax>
                <SimUsed>0</SimUsed>
                <NewMsg>2</NewMsg>
        </response>
        '''

        return self.__get( '/api/sms/sms-count')

    def send_sms(self, phone, message, index=0):
        """Send a sms to a given phone
        """

        now = datetime.now()
        # FIXME: do we need better way to generate XML ?
        # FIXME: do we need to find correct index ?
        payload = (
            '<?xml version: "1.0" encoding="UTF-8"?>'+"\n"
            '<request><Index>'+str( index)+'</Index>'
                '<Phones><Phone>'+escape(phone)+'</Phone></Phones>'
                '<Sca></Sca>'
                '<Content>'+escape(message)+'</Content>'
                '<Length>'+str( len( message))+'</Length>'
                '<Reserved>1</Reserved>'
                '<Date>'+now.strftime('%Y-%m-%d %H:%M:%S')+'</Date>'
            '</request>'
        )

        return self.__post( "/api/sms/send-sms", payload)

    def sms_count_contact(self, phone=None):
        '''count messages for a given phone

        Debug:
        <?xml version="1.0" encoding="utf-8"?>
        <response>
        <count>5</count>
        </response>
        '''

        # for scope
        data=None

        if phone == None:
            data = self.__get( "/api/sms/sms-count-contact")

        else:
            payload='<?xml version: "1.0" encoding="UTF-8"?><request><phone>'+escape(phone)+'</phone></request>'
            data = self.__post( '/api/sms/sms-count-contact', payload)

        return int( data.get("count"))


    def sms_list_contact( self, index=1, count=20):
        '''get all contacts with last message associated

        <?xml version="1.0" encoding="utf-8"?>
        <response>
                <Count>2</Count>
                <messages>
                        <message>
                                <smstat>1</smstat>
                                <index>40013</index>
                                <phone>+33123456789</phone>
                                <content>Yeehaa it's working !</content>
                                <date>2020-11-21 16:45:44</date>
                                <sca></sca>
                                <savetype>0</savetype>
                                <priority>0</priority>
                                <smstype>1</smstype>
                                <unreadcount>0</unreadcount>
                        </message>
                        <message>
                                <smstat>1</smstat>
                                <index>40005</index>
                                <phone>Free Mobile</phone>
                                <content>INFO FREE :...</content>
                                <date>2020-11-20 11:13:48</date>
                                <sca></sca>
                                <savetype>0</savetype>
                                <priority>0</priority>
                                <smstype>2</smstype>
                                <unreadcount>0</unreadcount>
                        </message>
                </messages>
        </response>
        '''

        payload = '<?xml version: "1.0" encoding="UTF-8"?><request><pageindex>'+str( index)+'</pageindex><readcount>'+str(count)+'</readcount></request>'
        data = self.__post( "/api/sms/sms-list-contact", payload)

        # XXX check for pagination
        count = int( data.get("Count", None))

        #for message in data.get("messages", None).get("message", None):
        #    print message

        if count == 1:
            return [ data.get("messages").get("message") ]
        else:
            return data.get("messages").get("message")

    def sms_list_phone( self, phone, index=1, count=20):
        '''
        <?xml version="1.0" encoding="UTF-8"?>
        <response>
        <count>13</count>
        <messages>
        <message>
        <smstat>3</smstat>
        <index>40000</index>
        <phone>+33123456789</phone>
        <content>Hello</content>
        <date>2020-11-11 17:07:34</date>
        <sca></sca>
        <curbox>1</curbox>
        <savetype>3</savetype>
        <priority>4</priority>
        <smstype>1</smstype>
        </message>
        ...
        <message>
        <smstat>1</smstat>
        <index>40013</index>
        <phone>+33123456789</phone>
        <content>Test only</content>
        <date>2020-11-21 16:45:44</date>
        <sca></sca>
        <curbox>0</curbox>
        <savetype>0</savetype>
        <priority>0</priority>
        <smstype>1</smstype>
        </message>
        </messages>
        </response>
        '''

        payload = '<?xml version: "1.0" encoding="UTF-8"?><request><phone>'+escape(phone)+'</phone><pageindex>'+str( index)+'</pageindex><readcount>'+str(count)+'</readcount></request>'
        data = self.__post( "/api/sms/sms-list-phone", payload)

        # XXX check for pagination
        count = int( data.get("count", None))

        if count == 1:
            return [ data.get("messages").get("message") ]
        else:
            return data.get("messages").get("message")


    def sms_set_read( self, index):
        """Ack a message

        Input:
            index <int> the message to acknowledge

        <?xml version="1.0" encoding="UTF-8"?><response>OK</response>
        """

        if not isinstance( index, list):
            index = [ index ]

        payload = '<?xml version: "1.0" encoding="UTF-8"?><request><Index>'+('</Index><Index>').join( map( lambda x : str(x), index))+'</Index></request>'

        return self.__post( "/api/sms/set-read", payload)


    def sms_delete_sms( self, index):
        """Delete one or multiple sms

        """

        if not isinstance( index, list):
            index = [ index ]

        payload = '<?xml version: "1.0" encoding="UTF-8"?><request><Index>'+('</Index><Index>').join( map( lambda x : str(x), index))+'</Index></request>'

        return self.__post( "/api/sms/delete-sms", payload)

    def sms_delete_phone( self, phone):
        """Delete one or multiple phones

        <?xml version: "1.0" encoding="UTF-8"?><request><Phones><Phone>+33123456789</Phone></Phones></request>
        """

        if not isinstance( phone, list):
            phone = [ phone ]


        payload = '<?xml version: "1.0" encoding="UTF-8"?><request><Phones><Phone>'+('</Phone><Phone>').join( map( lambda x : str(x), phone))+'</Phone></Phones></request>'

        return self.__post( "/api/sms/sms-delete-phone", payload)

    def switch_modem(self, state=None):
        '''Read or Activate data modem
        '''

        if state == None:
            return self.__get( '/api/dialup/mobile-dataswitch').get('dataswitch') == '1'

        if state:
            #activate modem (4g)
            return self.__post( '/api/dialup/mobile-dataswitch', '<?xml version: "1.0" encoding="UTF-8"?><request><dataswitch>1</dataswitch></request>')
        else:
            #disable modem (4g)
            return self.__post( '/api/dialup/mobile-dataswitch', '<?xml version: "1.0" encoding="UTF-8"?><request><dataswitch>0</dataswitch></request>')


    def dialup_connection( self):
        '''Get dialup connection information

        return
            ('RoamAutoConnectEnable', u'0')
            ('MaxIdelTime', u'0')
            ('ConnectMode', u'0')
            ('MTU', u'1500')
            ('auto_dial_switch', u'1')
            ('pdp_always_on', u'0')
        '''
        return self.__get( "/api/dialup/connection")

    def reboot( self):
        '''reboot device

        beware: you will have to if up usb ethernet if your host is not configured to do it automatically...

        '''
        return self.__post( '/api/device/control', '<?xml version: "1.0" encoding="UTF-8"?><request><Control>1</Control></request>')



# -------------------------------------------------------------------------------------------------------

def main():


    e3372 = HuaweiE3372()

    print "device phone number: "+e3372.get_phone();

    #print e3372.traffic_statistics()
    #print e3372.get_provider()
    #print e3372.dialup_connection()
    #print e3372.device_signal();

    
    #for path in e3372.XML_APIS:
    #    print(path)
    #    for key,value in e3372.get(path).items():
    #      print(key,value)
    #return


    #print e3372.switch_modem( False)
    #print e3372.switch_modem( )
    #print e3372.switch_modem( True)
    #print e3372.switch_modem( )

    print e3372.check_notifications()
    print e3372.sms_count()
    print e3372.sms_count_contact()

    contacts = e3372.sms_list_contact()

    lastindex = 0

    for contact in contacts:


        #print "From: "+contact["phone"]+" message: "+contact["content"]

        # get first phone in contact
        phone = contact["phone"]

        print "--------------- "+phone+" has "+str( e3372.sms_count_contact( phone))+" messages "

        print contact

        messages = e3372.sms_list_phone(  phone)
        for message in messages:
            print "message:"
            print message
            index = int( message['index'])

            if index > lastindex:
                lastindex = index


            if False and int( message['smstat']) == 0:
                # unread message, acknowledge it
                #XXX: could we ack all in 1 request ?
                print "acknowledge message ..."
                print e3372.sms_set_read( index);

    #print e3372.send_sms( phone, "fin transaction!", lastindex+1)
    #print e3372.sms_delete_sms( [index])
    #print e3372.sms_delete_phone( [1, 2])

if __name__ == "__main__":
    main()

