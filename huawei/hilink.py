#!/usr/bin/env python3
# coding=utf-8
# vim: set fileencoding=utf-8 :

import sys
import logging

import requests
import xmltodict
import dicttoxml

import secrets # python3 only 
import hashlib
import hmac


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

class AuthentificationException(ResponseException):
    pass

class SessionException(ResponseException):
    pass

class NetworkException(ResponseException):
    pass

class SmsException(ResponseException):
    pass

class WifiException(ResponseException):
    pass

errorCategoryMapping={
    100: ResponseException,
    125: SessionException,
    108: AuthentificationException,
    111: NetworkException, 
    113: SmsException,
    117: WifiException
}

errorMessageMapping={
    # generic
    100001: "system unknown",
    100002: "resource not supported",
    100003: "no rights",
    100004: "system busy",
    100005: "missing or wrong argument",
    100010: "object not found",

    #Auth
    108001: "wrong username",
    108002: "wrong password",
    108003: "already logged in",
    108005: "too many sessions opened",
    108006: "wrong password",
    108007: "too many failures, please wait",
    108009: "logged in with different devices",
    108010: "frequently login", # XXX meaning ?

    #Sms
    113055: "sms already changed",
    113114: "sms not found",

    #?
    115002: "cannot change user/password",

    #Session
    125001: "wrong token",
    125002: "wrong session",
    125003: "invalid token"
}


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

        var MACRO_NET_WORK_TYPE_GPRS = '2';
        var MACRO_NET_WORK_TYPE_EDGE = '3';
        var MACRO_NET_WORK_TYPE_WCDMA = '4';
        var MACRO_NET_WORK_TYPE_HSDPA = '5';
        var MACRO_NET_WORK_TYPE_HSUPA = '6';
        var MACRO_NET_WORK_TYPE_HSPA = '7';
        var MACRO_NET_WORK_TYPE_TDSCDMA = '8';
        var MACRO_NET_WORK_TYPE_HSPA_PLUS = '9';
        var MACRO_NET_WORK_TYPE_EVDO_REV_0 = '10';
        var MACRO_NET_WORK_TYPE_EVDO_REV_A = '11';
        var MACRO_NET_WORK_TYPE_EVDO_REV_B = '12';
        var MACRO_NET_WORK_TYPE_1XRTT = '13';
        var MACRO_NET_WORK_TYPE_UMB = '14';
        var MACRO_NET_WORK_TYPE_1XEVDV = '15';
        var MACRO_NET_WORK_TYPE_3XRTT = '16';
        var MACRO_NET_WORK_TYPE_HSPA_PLUS_64QAM = '17';
        var MACRO_NET_WORK_TYPE_HSPA_PLUS_MIMO = '18';
        var MACRO_NET_WORK_TYPE_LTE = '19';
        var MACRO_NET_WORK_TYPE_LTE_NR = '20';
        var MACRO_NET_WORK_TYPE_EX_NOSERVICE = '0';
        var MACRO_NET_WORK_TYPE_EX_GSM = '1';
        var MACRO_NET_WORK_TYPE_EX_GPRS = '2';
        var MACRO_NET_WORK_TYPE_EX_EDGE = '3';
        var MACRO_NET_WORK_TYPE_EX_IS95A = '21';
        var MACRO_NET_WORK_TYPE_EX_IS95B = '22';
        var MACRO_NET_WORK_TYPE_EX_CDMA_1X = '23';
        var MACRO_NET_WORK_TYPE_EX_EVDO_REV_0 = '24';
        var MACRO_NET_WORK_TYPE_EX_EVDO_REV_A = '25';
        var MACRO_NET_WORK_TYPE_EX_EVDO_REV_B = '26';
        var MACRO_NET_WORK_TYPE_EX_HYBRID_CDMA_1X = '27';
        var MACRO_NET_WORK_TYPE_EX_HYBRID_EVDO_REV_0 = '28';
        var MACRO_NET_WORK_TYPE_EX_HYBRID_EVDO_REV_A = '29';
        var MACRO_NET_WORK_TYPE_EX_HYBRID_EVDO_REV_B = '30';
        var MACRO_NET_WORK_TYPE_EX_EHRPD_REL_0 = '31';
        var MACRO_NET_WORK_TYPE_EX_EHRPD_REL_A = '32';
        var MACRO_NET_WORK_TYPE_EX_EHRPD_REL_B = '33';
        var MACRO_NET_WORK_TYPE_EX_HYBRID_EHRPD_REL_0 = '34';
        var MACRO_NET_WORK_TYPE_EX_HYBRID_EHRPD_REL_A = '35';
        var MACRO_NET_WORK_TYPE_EX_HYBRID_EHRPD_REL_B = '36';
        var MACRO_NET_WORK_TYPE_EX_WCDMA = '41';
        var MACRO_NET_WORK_TYPE_EX_HSDPA = '42';
        var MACRO_NET_WORK_TYPE_EX_HSUPA = '43';
        var MACRO_NET_WORK_TYPE_EX_HSPA = '44';
        var MACRO_NET_WORK_TYPE_EX_HSPA_PLUS = '45';
        var MACRO_NET_WORK_TYPE_EX_DC_HSPA_PLUS = '46';
        var MACRO_NET_WORK_TYPE_EX_TD_SCDMA = '61';
        var MACRO_NET_WORK_TYPE_EX_TD_HSDPA = '62';
        var MACRO_NET_WORK_TYPE_EX_TD_HSUPA = '63';
        var MACRO_NET_WORK_TYPE_EX_TD_HSPA = '64';
        var MACRO_NET_WORK_TYPE_EX_TD_HSPA_PLUS = '65';
        var MACRO_NET_WORK_TYPE_EX_802_16E = '81';
        var MACRO_NET_WORK_TYPE_EX_LTE = '101';
        var MACRO_NET_WORK_TYPE_EX_LTE_PLUS = '1011';
        var MACRO_NET_WORK_TYPE_EX_NR = '111';


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
    UCS2        = 0
    SEVEN_BIT   = 1
    EIGHT_BIT   = 2



# -------------------------------------------------------------------------------------- 

class HuaweiE3372(object):
    BASE_URL = 'http://{host}'
    COOKIE_URL = '/html/index.html'
    session = None

    def __init__(self, host='192.168.8.1'):

        self.host = host
        self.base_url = self.BASE_URL.format(host=host)
        self.session = requests.Session()
        self.tokens = []

        # get a session cookie by requesting the COOKIE_URL
        r = self.session.get(self.base_url + self.COOKIE_URL)


    def __api_decode( self, response, purgeToken=False):
        '''helper to decode answer from API
        '''

        # raise exception if status is not 200 OK
        response.raise_for_status()

        # purge previous tokens for methods like challenge_login, authentication_login 
        if purgeToken:
            self.tokens=[]
        else:
            if '__RequestVerificationTokenone' in response.headers:
                token=response.headers[ '__RequestVerificationTokenone' ]
                _LOGGER.debug("found token %s", token)
                self.tokens.append( token)
                if '__RequestVerificationTokentwo' in response.headers:
                    token=response.headers[ '__RequestVerificationTokentwo' ]
                    _LOGGER.debug("found token %s", token)
                    self.tokens.append( token)
            elif '__RequestVerificationToken' in response.headers:
                token=response.headers[ '__RequestVerificationToken' ]
                _LOGGER.debug("found token %s", token)
                self.tokens.append( token)

        # Don't check content-type as it is always a text/html event for pure XML answer

        xml = response.content.decode('utf-8')

        _LOGGER.debug("answer: %s", xml)

        try:
            data = xmltodict.parse( xml)
        except xmltodict.ExpatError:
            raise ValueError( "parsing error")

        if "error" in data:

            code    = int( data['error']['code'])
            message = data['error']['message']

            errorCategory= int(code/1000);

            # identify the best Exception category
            try:
                errorClass=errorCategoryMapping[ errorCategory]
            except KeyError:
                errorClass=ResponseException

            # identify the message message if not defined
            if message == None or len(message) == 0:
                try:
                    message = errorMessageMapping[ code ]
                except KeyError:
                    message = "error {code}".format( code=code)

            raise errorClass( message)

        if not "response" in data:
            raise ValueError("parse exception")

        return data.get("response", None)

    def __get(self, path):

        _LOGGER.info( "GET %s", path)

        return self.__api_decode( self.session.get( self.base_url + path))

    def get(self, path):
        return self.__get( path)

    def __get_token(self):
        data=self.__get( "/api/webserver/token")

        token = data.get('token', None); 
        
        token = token[32:]# take only from 32 chars (seen in: public.js)

        _LOGGER.debug( "explicitely fetched token %s", token)

        self.tokens.append( token);

    def __post_raw( self, 
            path, 
            payload,
            autoToken=True,
            headers={},
            purgeToken=False
        ):

        
        headers = { 
            #'content-type': 'text/xml; charset=utf-8',
            #'Origin': 'http://192.168.8.1',
            #'Referer': 'http://192.168.8.1/html/index.html?noredirect',
            #'User-Agent': 'Mozilla/5.0 X-Requested-With: XMLHttpRequest'
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8;', # yes this is not a x-www-form-urlencoded, but keep the same header as original
            '_ResponseSource': 'Broswer',                                        # kept typo from javascript :)
            **headers
        }

        if autoToken:

            # get token only if necessary
            if len( self.tokens) == 0:
                self.__get_token()

            # take the oldest token (first in list)
            token = self.tokens.pop(0)

            headers['__RequestVerificationToken'] = token

            #DEBUG print "using token "+token

        _LOGGER.info( "POST %s with %s", path, payload)
        _LOGGER.info( "with headers: %s", headers)

        response= self.session.request( 
            'POST', 
            self.base_url + path,
            headers=headers,
            data = payload
        )

        return self.__api_decode( response, purgeToken=purgeToken)

    def __post_request( self, 
            path,
            data, 
            item_func=lambda node: node[:-1], # ex: <Phones> will contains array of <Phone>
            autoToken=True,
            headers={},
            purgeToken=False
        ):

        payload = dicttoxml.dicttoxml( 
            data, 
            custom_root='request', 
            attr_type=False, 
            item_func=item_func
        )

        return self.__post_raw( 
                path, 
                payload, 
                autoToken=autoToken, 
                headers=headers,
                purgeToken=False
        )

    # -------------------------------------------------- user
    def user_login_required( self):
        # debug <response><hilink_login>1</hilink_login></response>
        return self.__get('/api/user/hilink_login').get('hilink_login') == '1'

    def user_state_login( self):
        """
        return dict
            password_type: 4
            extern_password_type: 1
            history_login_flag: 0
            State: -1
            lockstatus: 0
            password_rule: 0
            accounts_number: 1
            rsapadingtype: 1
            remainwaittime: 0
            wifipwdsamewithwebpwd: 0
            username: None
            firstlogin: 1
            userlevel: None
        """
        return self.__get('/api/user/state-login')

    def user_challenge_login( self, username="admin", firstnonce=None, mode=1):
        """Low level method"""

        '''

        returns dict:
            salt: ef08b9....
            modeselected: 1
            servernonce: 96701...
            newType: 0
            iterations: 100
        '''

       
        return self.__post_request( 
            "/api/user/challenge_login",
            OrderedDict( [
                ('username',    username),
                ('firstnonce',  firstnonce),
                ('mode',        mode),
            ]),
            purgeToken=True
        )

    def user_authentication_login( self, clientproof, finalnonce ):
        """Low level method"""

        return self.__post_request( 
            "/api/user/authentication_login",
            OrderedDict( [
                ( 'clientproof', clientproof ), 
                ( 'finalnonce',  finalnonce  )  
                # (loginflag , 2) # XXX in which case ? (@see: index.js)
            ]),
            purgeToken=True
        )

    def login( self, user, password):
        ''' Highlevel method to login

        returns dict: 
            serversignature: a74c...
            rsapubkeysignature: 303c...
            rsae: 010001
            rsan: a98c...


        Helper for tests/debug:

            input: 
                firstnonce = "6513d4a1bfa0d6b3a7e3320dc6b3b1cd703a479d4958b5e1462658d75f0c5029"
                password   = b'test'

            fake challenge answer:
                challenge = {
                    'salt':"ef08b9902cfb555135d098952c6d4ce629d52a3e835d4831147c96081538113c",
                    'servernonce':"6513d4a1bfa0d6b3a7e3320dc6b3b1cd703a479d4958b5e1462658d75f0c5029BsP0n8rghqsOgEbevsDvKnn0eCjBfed2",
                    'iterations':"100"
                }

            expect:
                saltedPassword.hex()  = 3bc1cc3158babe19edca5b7f354079fe0f37ea2dc75d9bbd8559e6751dd0380b
                clientKey.hex()       = 437f560be043f363cf3313c691f702c941d10a2093bcf3d7168922888e461f69
                storedKey.hex()       = 041b20524f91ca829da22a8e0c81387eeee56f207eaabb077b1912e7eb0e766b
                clientSignature.hex() = acbe62f1231b408287f534d27b1e4c14e9c53260775dccc5e1aafc7674dbd576
                clientProof.hex()     = efc134fac358b3e148c62714eae94edda8143840e4e13f12f723defefa9dca1f

        '''

        firstnonce = secrets.token_hex( 32)
        challenge =  self.user_challenge_login( firstnonce=firstnonce)

        salt       = challenge["salt"]
        finalnonce = challenge["servernonce"]
        iterations = int( challenge["iterations"])

        # do signature
        authMessage = b','.join( [ firstnonce.encode('utf-8'),  finalnonce.encode('utf-8'), finalnonce.encode('utf-8') ])

        saltedPassword = hashlib.pbkdf2_hmac( 'sha256', password, bytes.fromhex( salt), iterations)
        _LOGGER.debug( "login> clientKey %s", saltedPassword.hex())

        clientKey = hmac.new( b"Client Key", saltedPassword, digestmod=hashlib.sha256).digest()
        _LOGGER.debug( "login> clientKey %s", clientKey.hex())

        hasher = hashlib.sha256()
        hasher.update( clientKey)
        storedKey = hasher.digest()
        _LOGGER.debug( "login> storedKey %s", storedKey.hex())

        clientSignature = hmac.new( authMessage, storedKey, digestmod="sha256").digest()
        _LOGGER.debug( "login> clientSignature %s", clientSignature.hex())

        # clientKey XOR clientSignature
        clientProof = bytes([_a ^ _b for _a, _b in zip( clientKey, clientSignature)])
        _LOGGER.debug( "login> clientProof %s", clientProof.hex())

        return self.user_authentication_login( 
                clientProof.hex(), # XML is expecting hex() encoding
                finalnonce 
        )

    def user_heartbeat( self):
        return self.__get( "/api/user/heartbeat")

    def user_logout( self):
        """ Close session """
        return self.__post_request( '/api/user/logout', { 'Logout': 1 })


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
                pci: '1'
                sc: None
                cell_id: '.....'
                rsrq: '-13.0dB'
                rsrp: '-106dBm'
                rssi: '-75dBm'
                sinr: '6dB'
                rscp: None
                ecio: None
                mode: '7'
                ulbandwidth: '15MHz'
                dlbandwidth: '15MHz'
                txpower: 'PPusch:22dBm PPucch:11dBm PSrs:22dBm PPrach:17dBm'
                tdd: None
                ul_mcs: 'mcsUpCarrier1:6'
                dl_mcs: 'mcsDownCarrier1Code0:1 mcsDownCarrier1Code1:0'
                earfcn: 'DL:1675 UL:19675'
                rrc_status: None
                rac: None
                lac: None
                tac: '5902'
                band: '3'
                nei_cellid: 'No1:1No2:62'
                plmn: '20815'
                ims: None
                wdlfreq: None
                lteulfreq: '17575'
                ltedlfreq: '18525'
                transmode: None
                enodeb_id: '0407729'
                cqi0: '32639'
                cqi1: '32639'
                ulfrequency: '1757500kHz'
                dlfrequency: '1852500kHz'
                arfcn: None
                bsic: None
                rxlev: None

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
            CurrentConnectTime: '2174'
            CurrentUpload: '390'
            CurrentDownload: '255'
            CurrentDownloadRate: '0'
            CurrentUploadRate: '0'
            TotalUpload: '1800371'
            TotalDownload: '687051'
            TotalConnectTime: '612412'
            showtraffic: '1'
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

    def monitoring_month_statistics( self):
        '''

        return dict:
            CurrentMonthDownload: 761721
            CurrentMonthUpload: 1828764
            MonthDuration: 930183
            MonthLastClearTime: 2020-11-13
            CurrentDayUsed: 23009
            CurrentDayDuration: 59403
        '''

        return self.__get( "/api/monitoring/month_statistics")

    def monitoring_start_date( self):

        '''
        return dict:
            StartDay: 1
            DataLimit: 50MB
            DataLimitAwoke: 0
            MonthThreshold: 90
            DayThreshold: 90
            SetMonthData: 1
            trafficmaxlimit: 52428800
            turnoffdataenable: 0
            turnoffdataswitch: 0
            turnoffdataflag: 0
        '''

        return self.__get( "/api/monitoring/start_date")



    # -------------------------------------------------- net

    def net_provider( self):
        ''' get provider name

        return dict: 
            State: '0'
            FullName: '...'
            ShortName: '...'
            Numeric: '...'
            Rat: '7'
            Spn: None
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

    def send_status( self):
        '''retreive sens status of last send-sms ?

        return dict:
            Phone: None
            SucPhone: None
            FailPhone: +33...
            TotalCount: 1
            CurIndex: 1
        '''

        return self.__get( "/api/sms/send-status")

    def sms_count_contact(self, phone=None):
        '''count messages for a given phone

        return int
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

        debug:
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
            RoamAutoConnectEnable: u'0'
            MaxIdelTime: u'0'
            ConnectMode: u'0'
            MTU: u'1500'
            auto_dial_switch: u'1'
            pdp_always_on: u'0'
        '''
        return self.__get( "/api/dialup/connection")

# ----------------------------------------------------------------------------------------------


