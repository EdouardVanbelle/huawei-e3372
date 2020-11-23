#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :

import sys
import pprint

import argparse
import logging

import huawei.hilink
import huawei.hilinkHelper

# FIXME: need to dig into UTF8 and unicode problems :)


# -------------------------------------------------------------------------------------------------------

PAGINATION=20

def browse( e3372):

    print "device phone number: "+e3372.device_information().get("Msisdn");

    print "Unread messages: "+e3372.monitoring_check_notifications().get("UnreadMessage")

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
            contact = huawei.hilinkHelper.Contact( phone, count=e3372.sms_count_contact( phone), driver=e3372)

            print contact

            message_index=1
            while True:

                messages = e3372.sms_list_phone(  phone, index=message_index, count=PAGINATION)

                for raw_message in messages:

                    message = huawei.hilinkHelper.Message( raw_message)
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
        print

    elif isinstance(o , list):
        for elem in o:
            human_renderer( elem, "  "+shift)
        print 

    else:
        if isinstance( o, unicode):
            o=o.encode( 'utf-8')
        print "{shift}{value}".format( shift=shift, value= o)

def main():

    logging.basicConfig()

    parser = argparse.ArgumentParser() #prog='PROG')
    #parser.add_argument('--foo', action='store_true', help='foo help')
    parser.add_argument('--host', default="192.168.8.1", help="IP address to query (default: %(default)s)")
    parser.add_argument('--verbose', '-v', action="count", help="verbose mode")
    parser.add_argument('--output',  '-o', default="human", choices=['human', 'bash', 'json'], help="output format (default: %(default)s)")
    subparser_section = parser.add_subparsers(dest='section', help='section name', title="section command")

    parser_device = subparser_section.add_parser('device', help='device operations (--help for details)')
    parser_device.add_argument('action', choices=['information','signal', 'reboot'], help='information')

    parser_monitoring = subparser_section.add_parser('monitoring', help='monitoring operation (--help for details)')
    parser_monitoring.add_argument('action', choices=[ 'statistics', 'status', 'notifications' ], help='net informations')

    parser_net = subparser_section.add_parser('net', help='net operation (--help for details)')
    parser_net.add_argument('action', choices=[ 'statistics', 'provider' ], help='net informations')

    parser_modem = subparser_section.add_parser('modem', help='modem actions (--help for details)')
    parser_modem.add_argument('action', choices=['status', 'on', 'off', 'connection'], help="status, on, off")

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

    parser_api = subparser_section.add_parser('api', help='helper call directly API')
    parser_api.add_argument('--path', required=True)


    args = vars( parser.parse_args())

    if args['verbose'] == 1:
        huawei.hilink.setLogLevel( logging.INFO)

    elif args['verbose'] > 1:
        huawei.hilink.setLogLevel( logging.DEBUG)

    # FIXME: choose correct renderer according choice
    render = human_renderer

    try:

        e3372 = huawei.hilink.HuaweiE3372( host=args['host'])

        #FIXME: I trust that we can easily enhance code below...


        if args['section'] == 'modem':

            if args['action'] == 'status':
                render( e3372.dialup_switch_modem( ))

            elif args ['action'] == 'on':
                render( e3372.dialup_switch_modem( True))

            elif args ['action'] == 'off':
                render( e3372.dialup_switch_modem( False))
    
            elif args ['action'] == 'connection':
                render( e3372.dialup_connection( ))

        elif args['section'] == 'net':

            if args['action'] == 'statistics':
                render( e3372.net_statistics())

            elif args['action'] == 'provider':
                render( e3372.net_provider())

      
        elif args['section'] == 'device':

            if args['action'] == 'information':
                render( e3372.device_information())

            elif args['action'] == 'signal':
                render( e3372.device_signal())

            elif args ['action'] == 'reboot':
                render( e3372.device_reboot())

        elif args['section'] == 'monitoring':

            if args['action'] == 'status':
                render( e3372.monitoring_status())

            elif args['action'] == 'notifications':
                render( e3372.monitoring_check_notifications())

            elif args['action'] == 'statistics':
                render( e3372.monitoring_statistics())

        elif args['section'] == 'sms':

            if args['action'] == 'status':
                render( e3372.sms_count())

            elif args['action'] == 'send':
                render( e3372.send_sms( args['phone'], args['message']))

            elif args['action'] == 'list':
                render( e3372.sms_list())

            elif args['action'] == 'browse':
                browse( e3372) 

            elif args['action'] == 'mack':
                render( e3372.sms_set_read( args['id']))

            elif args['action'] == 'mdel':
                render( e3372.sms_delete_sms( args['id']))

            elif args['action'] == 'cdel':
                render( e3372.sms_delete_phone( args['phone']))
          
        elif args['section'] == 'api':
            render( e3372.get( args['path']))

        else:
            print "work in progress..."
            return

    except huawei.hilink.ResponseException as e:
        print e

if __name__ == "__main__":
    main()

