#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :

import re
import huawei.hilink

# -------------------------------------------------------------------------------------- 
# helper 
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

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# -------------------------------------------------------------------------------------- 

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
        self.status   = huawei.hilink.SmsStatus( int( raw['smstat']))
        self.type     = huawei.hilink.SmsType( int( raw['smstype']))
        self.priority = int( raw['priority'])
        self.savetype = int( raw['savetype'])

        #FIXME this seems not to be the SmsBoxType
        #if 'curbox' in raw:
        #    self.box      = huawei.hilink.SmsBoxType( int( raw['curbox']))

        # XXX meaning of "unreadcount" ? 

        self.unread    = (self.status == huawei.hilink.SmsStatus.ReceivedUnseen)
        self.canResend = (self.status == huawei.hilink.SmsStatus.SentError or self.status == huawei.hilink.SmsStatus.Draft)

        if contact != None:
            contact.append( self)



    def __str__( self):
        new=">"
        color=bcolors.OKGREEN

        if self.status == huawei.hilink.SmsStatus.ReceivedSeen:
            new="<"
            color=bcolors.OKCYAN
        elif self.status == huawei.hilink.SmsStatus.ReceivedUnseen:
            color=bcolors.OKCYAN
            new=bcolors.BOLD+"N"+bcolors.ENDC
        elif self.status == huawei.hilink.SmsStatus.SentError:
            color=bcolors.WARNING
            new=bcolors.BOLD+"!"+bcolors.ENDC

        return u"  {number} {new} {date} {color}{content}{endcolor}".format( 
                number=self.id, new=new, phone=self.phone, date=self.date, content=self.content, _type=self.type.name, color=color, endcolor=bcolors.ENDC
        )

    def __repr__( self):
        return u"<Message id:{number} unread:{unread} phone:{phone} date:{date} status:{status} content:{content}>".format( 
                    number=self.id, unread=self.unread, phone=self.phone, date=self.date, content=self.content, status=self.status
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


# -------------------------------------------------------------------------------------- 

class Contact(object):

    def __init__( self, phone, count=0, driver=None):
        self.driver = driver
        self.phone  = phone
        self.count  = count
        self.messages = {}

    def __str__( self):
        return u"Conversation with {phone} (msg: {count})".format( phone=self.phone, count=self.count)

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
 
