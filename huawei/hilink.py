#!/usr/bin/env python3
# coding=utf-8
# vim: set fileencoding=utf-8 :

import sys
import logging

import requests
import xmltodict
import dicttoxml

from collections import OrderedDict
from datetime import datetime
import enum

# -------------------------------------------------------------------------------------- 

_LOGGER = logging.getLogger(__name__)

def setLogLevel( level):
    _LOGGER.setLevel( level)

# -------------------------------------------------------------------------------------- 

class ResponseException(Exception):
    pass

# -------------------------------------------------------------------------------------- 
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

    NetworkType:
        0 = 'No Service'
        1 = 'GSM'
        2 = 'GPRS (2.5G)'
        3 = 'EDGE (2.75G)'
        4 = 'WCDMA (3G)'
        9 = 'HSPA+ (4G)'



'''

@enum.unique
class SmsType(enum.IntEnum):
    Simple          = 1 # classic SMS
    Aggregated      = 2 # more than 160 chars
    MMS4            = 4 # MMS (unmanaged case) 
    MMS5            = 5 # MMS (unmanaged case)
    MMS6            = 6 # MMS (unmanaged case)
    ReportSuccess   = 7
    ReportFailed    = 8
    Alert           = 9
    Info            = 10


@enum.unique
class SmsStatus(enum.IntEnum):
    ReceivedUnseen = 0
    ReceivedSeen   = 1
    Draft          = 2
    SentOk         = 3
    SentError      = 4

@enum.unique
class SmsCharset(enum.IntEnum):
    UCS2 = 0
    SEVEN_BIT = 1
    EIGHT_BIT = 2


# -------------------------------------------------------------------------------------- 

class HuaweiE3372(object):
    BASE_URL = 'http://{host}'
    COOKIE_URL = '/html/index.html'

    # all unmapped APIs
    # details also available on: https://blog.hqcodeshop.fi/archives/259-Huawei-E5186-AJAX-API.html
    #XML_APIS = [
    #    '/api/device/basic_information',
    #    '/api/global/module-switch',
    #    '/api/net/net-mode',
    #]
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

        # raise exception if status is not 200 OK
        response.raise_for_status()

        # check additional token in answer
        if '__RequestVerificationToken' in response.headers:
            self.tokens.append( response.headers['__RequestVerificationToken'])
            #DEBUG print "additional token "+response.headers['__RequestVerificationToken']

        # Don't check content-type as it is always a text/html event for pure XML answer

        xml = response.content

        _LOGGER.debug("answer: %s", xml)

        try:
            data = xmltodict.parse( xml)
        except xmltodict.ExpatError:
            raise ResponseException( 0, "answer parsing error")

        if "error" in data:

            code    = int( data['error']['code'])
            message = data['error']['message']

            #FIXME should use better exception
            if   code == 100002:
                raise ResponseException( code, "resource not found")
            elif code == 100010:
                raise ResponseException( code, "object not found")
            elif code == 100005:
                raise ResponseException( code, "missing or wrong argument")
            elif code == 125003:
                raise ResponseException( code, "invalid token")
            elif code == 113055: 
                raise ResponseException( code, "sms already changed")
            elif code == 113114:
                raise ResponseException( code, "sms not found")
            else:
                # unknown case
                raise ResponseException( code, message)

        if not "response" in data:
            raise Exception("parse exception")

        return data.get("response", None)

    def __get(self, path):

        _LOGGER.info( "GET %s", path)

        return self.__api_decode( self.session.get( self.base_url + path))

    def get(self, path):
        return self.__get( path)

    def __get_token(self):
        data=self.__get( "/api/webserver/token")

        token = data.get('token', None);

        _LOGGER.debug( "got token %s", token)

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

        #DEBUG print "using token "+token

        _LOGGER.info( "POST %s with %s", path, payload)

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

    # -------------------------------------------------- device

    def device_information( self):
        '''get device information

        return dict with keys: 
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

            return dict: 
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

    def device_reboot( self):
        '''reboot device

        beware: you will have to if up usb ethernet if your host is not configured to do it automatically...

        '''
        return self.__post_request( '/api/device/control', { 'Control': 1 })


    # -------------------------------------------------- monitoring

    def monitoring_statistics( self):
        '''return statistics

        return dict: 
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

    def monitoring_status( self):

        return self.__get( "/api/monitoring/status")

    def monitoring_check_notifications( self):
        '''Check for notifications

        return dict:
            UnreadMessage
            SmsStorageFull
            OnlineUpdateStatus
            SimOperEvent
        '''

        # FIXME: should map response
        return self.__get( '/api/monitoring/check-notifications')

    # -------------------------------------------------- net

    def net_provider( self):
        ''' get provider name

        return dict: 
            ('State', '0')
            ('FullName', '...')
            ('ShortName', '...')
            ('Numeric', '...')
            ('Rat', '7')
            ('Spn', None)
        '''
        return self.__get('/api/net/current-plmn');

    # -------------------------------------------------- sms

    def sms_config( self):
        '''get configuration

        return dict:
            SaveMode: 0
            Validity: 10752
            Sca: +33695000695 # <- this is the sms message number
            UseSReport: 0
            SendType: 1
            pagesize: 20
            maxphone: 50
            import_enabled: 1
            url_enabled: 1
            cdma_enabled: 0
            smscharlang: 0
            smsisusepdu: 0
            sms_center_number_editabled: 0
            sms_forward_enable: 0
            switch_enable: 0
            country_number: None
            phone_number: None
        '''

        # FIXME: check to define setter:
        # with: <?xml version: "1.0" encoding="UTF-8"?><request><SaveMode>0</SaveMode><Validity>10752</Validity><Sca> 33695000695</Sca><UseSReport>1</UseSReport><SendType>1</SendType><switch_enable>0</switch_enable><country_number></country_number><phone_number></phone_number><Priority></Priority></request>
        # UseSReport = Use Sms Report (purpose =?)

        return self.__get('/api/net/config');

    def sms_splifinfo( self):
        ''' unknown purpose

        return dict:
            splitinfo: 1
            convert_type: 2
        '''
        return self.__get('/api/sms/splitinfo-sms');

    def sms_feature_switch( self):
        ''' unknwon purpose

        return dict:
            getcontactenable: 0
        '''

        return self.__get('/api/sms/sms-feature_switch');


    def sms_count( self):
        '''Sms count
           Important:calling this method also force to refresh sms list 

        return dict:
            LocalUnread: 6
            LocalInbox: 21
            LocalOutbox: 14
            LocalDraft: 0
            LocalDeleted: 0
            SimUnread: 0
            SimInbox: 0
            SimOutbox: 0
            SimDraft: 0
            LocalMax: 500
            SimMax: 100
            SimUsed: 0
            NewMsg: 0
        '''

        return self.__get( '/api/sms/sms-count')

    # lazy shortcut
    def sms_refresh( self):
        return self.sms_count()


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

    def sms_list(self,
             boxtype=1, 
             page=1,
             count=20,
             sorttype=0,
             ascending=0,
             unreadpreferred=0
        ):
        ''' list sms in a given box 
        '''

        #beware uppercase here
        data = self.__post_request(
            '/api/sms/sms-list',
            OrderedDict([
                ('PageIndex',       page),
                ('ReadCount',       count),
                ('BoxType',         boxtype),
                ('SortType',        sorttype),
                ('Ascending',       ascending),
                ('UnreadPreferred', unreadpreferred),
            ])
        )

        #beware uppercase here

        if data.get("Messages") == None:
            return []

        messages = data.get("Messages").get("Message")

        # normalize answer (always an array)
        if not isinstance( messages, list):
            messages = [ messages ]

        return messages

    def sms_list_contact( self, page=1, count=20):
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
                ('pageindex', page), 
                ('readcount', count)
            ])
        )

        if data.get("messages") == None:
            return []

        messages = data.get("messages").get("message")

        # normalize answer (always an array)
        if not isinstance( messages, list):
            messages = [ messages ]

        return messages

    def sms_list_phone( self, phone, page=1, count=20):
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
                ('pageindex', page),
                ('readcount', count)
            ] )
        )

        if data.get("messages") == None:
            return []

        messages = data.get("messages").get("message")

        # normalize answer (always an array)
        if not isinstance( messages, list):
            messages = [ messages ]

        return messages


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

    # -------------------------------------------------- dialup

    def dialup_switch_modem(self, state=None):
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

# ----------------------------------------------------------------------------------------------


