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
        1
        2
        4 5 6: multisms
        7: smsreport (success)
        8: smsreport (failed)
        9: alert
        10: info
'''

class HuaweiE3372(object):
    BASE_URL = 'http://{host}'
    COOKIE_URL = '/html/index.html'
    XML_APIS = [
#    '/api/device/basic_information',
#    '/api/device/information',
#    '/api/device/signal',
#    '/api/monitoring/status',
#    '/api/monitoring/traffic-statistics',
#    '/api/dialup/connection',
#    '/api/global/module-switch',
#    '/api/net/current-plmn',
#    '/api/net/net-mode',
#    '/api/sms/sms-count',
#    '/api/monitoring/check-notifications',  
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

        xml = response.text

        # ensure we have a XML answer
        if not xml.startswith( "<?xml", 0, 5):
            raise Exception( "This is not a XML answer")

        data = xmltodict.parse( xml)

        if "error" in data:
            raise Exception( data['error']['code'], data['error']['message'])

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

    # FIXME
    """
    GET http://192.168.8.1/api/sms/sms-count-contact

    <response>
    <count>2</count>
    </response>
    """

    def sms_count_contact(self, phone):
        '''count messages for a given phone

        Debug:
        <?xml version="1.0" encoding="utf-8"?>
        <response>
        <count>5</count>
        </response>
        '''

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

        count = int( data.get("Count", None))
        print "count: "+str(count)
        for message in data.get("messages", None).get("message", None):
            print message

        return data.get("messages", None).get("message", None)

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

        print data

        # FIXME
        count = int( data.get("count", None))
        print "count "+str(count)

        if count == 1:
            return [ data.get("messages").get("message") ]
        else:
            return data.get("messages", None).get("message")


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



# -------------------------------------------------------------------------------------------------------

def main():


    e3372 = HuaweiE3372()

    return
    print e3372.check_notifications()
    print e3372.sms_count()

    #print e3372.sms_count_contact( phone)

    contacts = e3372.sms_list_contact()

    for contact in contacts:
        print "From: "+contact["phone"]+" message: "+contact["content"]

    # get first phone in contact
    phone = contacts[0]["phone"]

    lastindex = 0

    messages = e3372.sms_list_phone( phone)
    for message in messages:
        print message
        index = int( message['index'])
        lastindex = index
        if int( message['smstat']) == 0:
            # unread message, acknowledge it
            print "acknowledge message ..."
            print e3372.sms_set_read( index);

    #print e3372.send_sms( phone, "fin transaction!", lastindex+1)
    #print e3372.sms_delete_sms( [index])
    #print e3372.sms_delete_phone( [1, 2])

    #for path in e3372.XML_APIS:
    #    print(path)
    #    for key,value in e3372.get(path).items():
    #      print(key,value)


if __name__ == "__main__":
    main()

