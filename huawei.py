#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :

import sys
import pprint
import requests
import xmltodict
import dicttoxml
import re
import argparse

from collections import OrderedDict
from datetime import datetime
from enum import IntEnum

# FIXME: need to dig into UTF8 and unicode problems :)


def norm_phone( phone):
    ''' normalize phone number to international form '''
       
    # FIXME: suppose that we are in France: +33, should use better mapping

    if re.match( '^\+', phone):
        return phone

    if re.match( '^00', phone):
        return '+'+phone[2:]

    if re.match( '^0[^0]', phone):
        return '+33'+phone[1:]
   
    #XXX: should not occurs, keep current format but should raise an exception
    return phone

class HuaweiE3372(object):
    BASE_URL = 'http://{host}'
    COOKIE_URL = '/html/index.html'

    # all unmapped APIs
    # details also available on: https://blog.hqcodeshop.fi/archives/259-Huawei-E5186-AJAX-API.html
    XML_APIS = [
        '/api/device/basic_information',
        '/api/global/module-switch',
        '/api/net/net-mode',
    ]
    session = None

    def __init__(self, host='192.168.8.1'):
        self.host = host
        self.base_url = self.BASE_URL.format(host=host)
        self.session = requests.Session()
        self.tokens = []
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

        xml = response.content

        # ensure we have a XML answer
        if not xml.startswith( "<?xml", 0, 5):
            raise Exception( "This is not a XML answer")

        #DEBUG print xml

        data = xmltodict.parse( xml)

        if "error" in data:

            '''
            format: 
              <error>
                <code>113055</code>
                <message></message>
              </error>
            '''


            code    = int( data['error']['code'])
            message = data['error']['message']

            if code == 100010:
                #FIXME should use better exception
                raise Exception( code, "object not found")
            elif code == 100005:
                #FIXME should use correct exception
                raise Exception( code, "missing argument")
            elif code == 125003:
                # invalid token
                raise Exception( code, "invalid token")
            elif code == 113055: 
                raise Exception( code, "sms already changed")
            elif code == 113114:
                raise Exception( code, "sms not found")
            else:
                # unknown case
                raise Exception( code, message)

        if not "response" in data:
            raise Exception("parse exception")

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

    def __post_raw( self, 
            path, 
            payload
        ):

        # get token only if necessary
        if len( self.tokens) == 0:
            self.__get_token()

        # take the oldest token (first in list)
        token = self.tokens.pop(0)

        if isinstance( payload, unicode):
            payload = payload.encode( 'utf-8')

        #DEBUG print "using token "+token
        #DEBUG print "sending to {path}: {payload}".format( path=path, payload=payload)

        # XXX: do we need to force content ? Content-Type: application/x-www-form-urlencoded; charset=UTF-8;
        return self.__api_decode( self.session.request( 
            'POST', 
            self.base_url + path,
            headers = { 
                '__RequestVerificationToken' : token,
                'content-type': 'text/xml; charset=utf-8'},
            data = payload
        ))

    def __post_request( self, 
            path,
            data, 
            item_func=lambda node: node[:-1] # ex: <Phones> will contains array of <Phone>
        ):

        payload = dicttoxml.dicttoxml( 
            data, 
            custom_root='request', 
            attr_type=False, 
            item_func=item_func
        )

        return self.__post_raw( path, payload)

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

        return self.__get('/api/device/information')

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
                ('pci', '1')
                ('sc', None)
                ('cell_id', '.....')
                ('rsrq', '-13.0dB')
                ('rsrp', '-106dBm')
                ('rssi', '-75dBm')
                ('sinr', '6dB')
                ('rscp', None)
                ('ecio', None)
                ('mode', '7')
                ('ulbandwidth', '15MHz')
                ('dlbandwidth', '15MHz')
                ('txpower', 'PPusch:22dBm PPucch:11dBm PSrs:22dBm PPrach:17dBm')
                ('tdd', None)
                ('ul_mcs', 'mcsUpCarrier1:6')
                ('dl_mcs', 'mcsDownCarrier1Code0:1 mcsDownCarrier1Code1:0')
                ('earfcn', 'DL:1675 UL:19675')
                ('rrc_status', None)
                ('rac', None)
                ('lac', None)
                ('tac', '5902')
                ('band', '3')
                ('nei_cellid', 'No1:1No2:62')
                ('plmn', '20815')
                ('ims', None)
                ('wdlfreq', None)
                ('lteulfreq', '17575')
                ('ltedlfreq', '18525')
                ('transmode', None)
                ('enodeb_id', '0407729')
                ('cqi0', '32639')
                ('cqi1', '32639')
                ('ulfrequency', '1757500kHz')
                ('dlfrequency', '1852500kHz')
                ('arfcn', None)
                ('bsic', None)
                ('rxlev', None)])

        '''
        return self.__get('/api/device/signal')

    def monitoring_statistics( self):
        '''return statistics

        values:
            ('CurrentConnectTime', '2174')
            ('CurrentUpload', '390')
            ('CurrentDownload', '255')
            ('CurrentDownloadRate', '0')
            ('CurrentUploadRate', '0')
            ('TotalUpload', '1800371')
            ('TotalDownload', '687051')
            ('TotalConnectTime', '612412')
            ('showtraffic', '1')
        '''

        return self.__get( "/api/monitoring/traffic-statistics")

    def monitoring_status():
        return self.__get( "/api/monitoring/status")

    def net_provider( self):
        ''' get provider name

        return:
            ('State', '0')
            ('FullName', '...')
            ('ShortName', '...')
            ('Numeric', '...')
            ('Rat', '7')
            ('Spn', None)
        '''
        return self.__get('/api/net/current-plmn');

    def get(self, path):
        return self.__get( path)

    def monitoring_check_notifications( self):
        '''Check for notifications

        return: {
            unreadMessage: <int>,
            smsStorageFull: <boolean>
        }

        Debug:
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

    def send_sms(self, phone, message, index=-1, date=None):
        """Send a sms to a given phone
        """

        if not isinstance( phone, list):
            phone = [ phone ]

        if date == None:
            date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return self.__post_request( 
            "/api/sms/send-sms", 
            OrderedDict( [
                ('Index',    index),
                ('Phones',   phone),
                ('Sca',      ""), # XXX: purpose ?
                ('Content',  message),
                ('Length',   len( message)),
                ('Reserved', SmsCharset.EIGHT_BIT.value), 
                ('Date',     date)
            ])
        )

    def get_sms_list(self,
             page=1,
             box_type=1, #BoxTypeEnum=BoxTypeEnum.LOCAL_INBOX,
             read_count=20,
             sort_type=0,
             ascending=0,
             unread_preferred=0
        ):
        return self.__post_request(
            '/api/sms/sms-list',
            OrderedDict([
                ('PageIndex', page),
                ('ReadCount', read_count),
                ('BoxType', box_type),
                ('SortType', sort_type),
                ('Ascending', ascending),
                ('UnreadPreferred', unread_preferred),
            ])
        )

    def sms_count_contact(self, phone=None):
        '''count messages for a given phone

        Debug:
        <response>
        <count>5</count>
        </response>
        '''

        # for scope
        data=None

        if phone == None:
            data = self.__get( "/api/sms/sms-count-contact")

        else:
            data = self.__post_request( '/api/sms/sms-count-contact', { 'phone' : phone })

        return int( data.get("count"))


    def sms_list_contact( self, index=1, count=20):
        '''get all contacts with last message associated

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

        data = self.__post_request( 
            "/api/sms/sms-list-contact", 
            OrderedDict( [ 
                ('pageindex', index), 
                ('readcount', count)
            ])
        )

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

        data = self.__post_request( 
            "/api/sms/sms-list-phone", 
            OrderedDict( [ 
                ('phone',     phone), 
                ('pageindex', index),
                ('readcount', count)
            ] )
        )

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

        <response>OK</response>
        """

        if not isinstance( index, list):
            index = [ index ]

        return self.__post_request( "/api/sms/set-read", index, item_func=lambda node: 'Index')


    def sms_delete_sms( self, index):
        """Delete one or multiple sms

        """

        if not isinstance( index, list):
            index = [ index ]

        return self.__post_request( "/api/sms/delete-sms", index, item_func=lambda node: 'Index')


    def sms_delete_phone( self, phone):
        """Delete one or multiple phones

        <request><Phones><Phone>+33123456789</Phone></Phones></request>
        """

        if not isinstance( phone, list):
            phone = [ phone ]

        return self.__post_request( "/api/sms/sms-delete-phone", { 'Phones' : phone } )

    def switch_modem(self, state=None):
        '''Read or Activate data modem
        '''

        if state == None:
            return self.__get( '/api/dialup/mobile-dataswitch').get('dataswitch') == '1'

        if state:
            #activate modem (4g)
            return self.__post_request( '/api/dialup/mobile-dataswitch', { 'dataswitch' : 1 } ) 
        else:
            #disable modem (4g)
            return self.__post_request( '/api/dialup/mobile-dataswitch', { 'dataswitch' : 0 } ) 


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

    def device_reboot( self):
        '''reboot device

        beware: you will have to if up usb ethernet if your host is not configured to do it automatically...

        '''
        return self.__post_request( '/api/device/control', { 'Control': 1 })

# ----------------------------------------------------------------------------------------------

'''
Try Reverse Eng:

    curbox:
        0 incoming
        1 outgoing

    savetype:
        3 sent
        0 received

     ConnectionStatus:
       900: connecting
       901: connected
       902: disconnected
       903: disconnecting
       ...

'''


class SmsType(IntEnum):
    Simple          = 1 # classic SMS
    Aggregated      = 2 # more than 160 chars
    MMS4            = 4 # MMS (unmanaged case) 
    MMS5            = 5 # MMS (unmanaged case)
    MMS6            = 6 # MMS (unmanaged case)
    ReportSuccess   = 7
    ReportFailed    = 8
    Alert           = 9
    Info            = 10


class SmsStatus(IntEnum):
    ReceivedUnseen = 0
    ReceivedSeen   = 1
    Draft          = 2
    SentOk         = 3
    SentError      = 4

class SmsCharset(IntEnum):
    UCS2 = 0
    SEVEN_BIT = 1
    EIGHT_BIT = 2

class Message(object):


    def __init__( self, raw, contact=None):
        ''' constructor

        from Contact (last message):
            #OrderedDict([(u'smstat', u'4'), (u'index', u'40020'), (u'phone', u'+3317821445'), (u'content', u"j'arrive"), (u'date', u'2020-11-21 21:52:02'), (u'sca', None), (u'savetype', u'3'), (u'priority', u'4'), (u'smstype', u'1'), (u'unreadcount', u'0')])
        from Messages:
            #OrderedDict([(u'smstat', u'4'), (u'index', u'40020'), (u'phone', u'+3317821445'), (u'content', u"j'arrive"), (u'date', u'2020-11-21 21:52:02'), (u'sca', None), (u'savetype', u'3'), (u'priority', u'4'), (u'smstype', u'1'), (u'curbox', u'2'), 
        '''

        self.contact  = contact
        self.id       = int( raw['index'])
        self.phone    = norm_phone( raw['phone'])
        self.content  = raw['content']
        self.date     = raw['date']
        self.status   = SmsStatus( int( raw['smstat']))
        self.type     = SmsType( int( raw['smstype']))
        self.priority = int( raw['priority'])
        self.savetype = int( raw['savetype'])

        # XXX: unreadcount and curbox are not relevant 

        #if self.content != None:
        #    self.content = self.content.encode('utf8')

        if self.status == SmsStatus.ReceivedUnseen or self.status == SmsStatus.ReceivedSeen:
            self.dir = u"incoming" 
        elif self.status == SmsStatus.SentError:
            self.dir = u"out-err " 
        elif self.status == SmsStatus.Draft:
            self.dir = u"draft   " 
        else:
            self.dir = u"outgoing"

        self.unread    = (self.status == SmsStatus.ReceivedUnseen)
        self.canResend = (self.status == SmsStatus.SentError or self.status == SmsStatus.Draft)

        if contact != None:
            contact.append( self)


    def __unicode__( self):
        new="-"

        if self.status == SmsStatus.ReceivedSeen:
            new="r"
        elif self.status == SmsStatus.ReceivedUnseen:
            new="N"
        elif self.status == SmsStatus.SentError:
            new='!'

        return u"Message #{number} {direction} [{new}] with {phone} at {date} ({status} {_type}): {content}".format( 
                number=self.id, new=new, direction=self.dir, phone=self.phone, date=self.date, content=self.content, status=str( self.status), _type=str( self.type)
        )

    def __str__( self):
        return unicode( self).encode('utf-8')

    def __repr__( self):
        return u"<Message id:{number} unread:{unread} dir:{direction} phone:{phone} date:{date} status:{status} content:{content}>".format( 
                    number=self.id, unread=self.unread, direction=self.dir, phone=self.phone, date=self.date, content=self.content, status=self.status
        )


    def ack( self):

        #FIXME: what if contact is not defined
        #FIXME: what if driver is not defined in contact
        driver = self.contact.driver

        try:
            driver.sms_set_read( self.id)
            self.unread = False 

        except:
            raise

    def drop( self):
        driver = self.contact.driver

        try:
            driver.sms_delete_sms( [ self.id])
            self.contact.remove( self)
        except:
            raise

    def resend( self):
        driver = self.contact.driver

        try:
            #XXX: do we need to keep use same date ?
            driver.send_sms( self.phone, self.content, index=self.id)
        except:
            # FIXME: need to understant error 113004 (§but message sucessfully sent)
            raise


       

class Contact(object):

    def __init__( self, phone, count=0, driver=None):
        self.driver = driver
        self.phone  = phone
        self.count  = count
        self.messages = {}

    def __unicode__(self):
        return u"Contact {phone} (msg: {count})".format( phone=self.phone, count=self.count)

    def __str__( self):
        return unicode( self).encode('utf-8')

    def __repr__(self):
        return u"<Contact phone:{phone} count:{count}>".format( phone=self.phone, count=self.count)

    def send( self, message):
        #FIXME: could get new
        #XXX driver must be set
        self.driver.send_sms( self.phone, message)

    def append( self, message, overwrite=False):

        if not overwrite and message.id in self.messages:
            return False

        message.contact = self
        self.messages[message.id] = message
        #self.messages.append( message)

        return True

    def remove( self, message):

        index=message
        if isinstance( message, Message):
            index=message.id

        self.messages.pop( index, None)
        #self.messages.remove( message)

    def exists( self, message):

        index=message
        if isinstance( message, Message):
            index=message.id

        return index in self.messages


    def sorted( self):
        '''get messages sorted by date'''
        return iter( sorted( self.messages, key=lambda index : self.messages[index].date))

    def drop( self):
        driver = self.driver

        try:
            driver.sms_delete_phone( [ self.phone ])
        except:
            raise
 
# -------------------------------------------------------------------------------------------------------

PAGINATION=20

def browse( e3372):

    print u"device phone number: "+e3372.device_information().get("Msisdn");

    print e3372.monitoring_check_notifications()

    print "Total contacts: {count}".format( count = e3372.sms_count_contact())


    contact_index=1
    while True:

        contacts = e3372.sms_list_contact( index=contact_index, count=PAGINATION)


        for raw_contact in contacts:

            print 

            if raw_contact['phone'] == None:
                print "got a dirty entry, try to purge it"
                print raw_contact

                if raw_contact['index'] != 0:
                    try:
                        print e3372.sms_delete_sms( [raw_contact['index']])
                    except: 
                        print "Unable to purge entry"

                continue

            # get first phone in contact
            phone=raw_contact["phone"]
            contact = Contact( phone, count=e3372.sms_count_contact( phone), driver=e3372)

            print contact

            message_index=1
            while True:

                messages = e3372.sms_list_phone(  phone, index=message_index, count=PAGINATION)

                for raw_message in messages:

                    message = Message( raw_message)
                    if not contact.append( message):
                        continue


                if len( messages) < PAGINATION:
                    # no more messages
                    break

                message_index += 1

                if message_index > 100:
                    raise Exception("Too much iterations, please check system")


            # now we have all message for a given contact, print them, sorted by date

            for index in contact.sorted():

                message = contact.messages[index]
                print message


            #if False and  contact.phone == "+33123456789":
            #    #print "delete first message"
            #    #contact.messages[0].drop() 



        if len(contacts) < PAGINATION:
            # no more contacts
            break

        contact_index += 1

        if contact_index > 100:
            raise Exception("Too much iterations, please check system")


# FIXME: enhance this code (currently crappy )
def human_renderer( o, shift=""):
    
    if isinstance( o, dict):
        for key, value in o.items():
            if isinstance( value, dict) or isinstance( value, list):
                print "{shift}{key}:".format( shift=shift, key=key)
                human_renderer( value, "   "+shift)
            else:
                if isinstance(value, unicode):
                    value=value.encode("utf-8")
                print "{shift}{key}: {value}".format( shift=shift, key=key, value=value)

    elif isinstance(o , list):
        for elem in o:
            human_renderer( elem, "  "+shift)
    else:
        if isinstance( o, unicode):
            o=o.encode( 'utf-8')
        print "{shift}{value}".format( shift=shift, value= o)

def main():


    parser = argparse.ArgumentParser() #prog='PROG')
    #parser.add_argument('--foo', action='store_true', help='foo help')
    parser.add_argument('--host', default="192.168.8.1", help="IP address to query (default: %(default)s)")
    parser.add_argument('--output',  '-o', default="human", choices=['human', 'bash', 'json'], help="output format (default: %(default)s)")
    subparser_section = parser.add_subparsers(dest='section', help='section name', title="section command")

    parser_device = subparser_section.add_parser('device', help='device operations (--help for details)')
    parser_device.add_argument('action', choices=['information','signal', 'reboot'], help='information')

    parser_monitoring = subparser_section.add_parser('monitoring', help='monitoring operation (--help for details)')
    parser_monitoring.add_argument('action', choices=[ 'status', 'notifications' ], help='net informations')

    parser_net = subparser_section.add_parser('net', help='net operation (--help for details)')
    parser_net.add_argument('action', choices=[ 'statistics', 'provider' ], help='net informations')

    parser_modem = subparser_section.add_parser('modem', help='modem actions (--help for details)')
    parser_modem.add_argument('action', choices=['status', 'on', 'off'], help="status, on, off")

    parser_sms = subparser_section.add_parser('sms', help='sms actions (--help for details)')
    parser_sms_action        = parser_sms.add_subparsers(dest='action', help='action name', title="section command")

    parser_sms_action_send   = parser_sms_action.add_parser( 'send', help="send sms")
    parser_sms_action_send.add_argument( "--phone", required=True)
    parser_sms_action_send.add_argument( "--message", required=True)

    parser_sms_action_browse = parser_sms_action.add_parser( 'browse', help="sms list")
    parser_sms_action_list   = parser_sms_action.add_parser( 'list', help="sms browse")
    parser_sms_action_status = parser_sms_action.add_parser( 'status', help="sms status")
    parser_sms_action_mack   = parser_sms_action.add_parser( 'mack', help="message acknowledge")
    parser_sms_action_mack.add_argument( "--id", required=True)

    parser_sms_action_mdel   = parser_sms_action.add_parser( 'mdel', help="message delete")
    parser_sms_action_mdel.add_argument( "--id", required=True)

    parser_sms_action_cdel   = parser_sms_action.add_parser( 'cdel', help="contact delete (and associated messages)")
    parser_sms_action_cdel.add_argument( "--phone", required=True)


    args = vars( parser.parse_args())

    # FIXME: choose correct renderer according choice
    render = human_renderer

    e3372 = HuaweiE3372( host=args['host'])


    if args['section'] == 'modem':

        if args['action'] == 'status':
            render( e3372.switch_modem( ))

        elif args ['action'] == 'on':
            render( e3372.switch_modem( True))

        elif args ['action'] == 'off':
            render( e3372.switch_modem( False))

    elif args['section'] == 'net':

        if args['action'] == 'statistics':
            render( e3372.net_statistics())

        elif args['action'] == 'provider':
            render( e3372.net_provider())

  
    elif args['section'] == 'device':

        if args['action'] == 'information':
            render( e3372.device_information())

        elif args['action'] == 'signal':
            render( e3372.device_signal().items())

        elif args ['action'] == 'reboot':
            render( e3372.device_reboot())

    elif args['section'] == 'sms':

        if args['action'] == 'status':
            render( e3372.sms_count())

        elif args['action'] == 'send':
            render( e3372.send_sms( args['phone'], args['message']))

        elif args['action'] == 'list':
            render( e3372.get_sms_list())

        elif args['action'] == 'browse':
            browse( e3372) 

        elif args['action'] == 'mack':
            render( e3372.sms_set_read( args['id']))

        elif args['action'] == 'mdel':
            render( e3372.sms_delete_sms( args['id']))

        elif args['action'] == 'cdel':
            render( e3372.sms_delete_phone( args['phone']))
      
    else:

        print "work in progress..."
        return


if __name__ == "__main__":
    main()

