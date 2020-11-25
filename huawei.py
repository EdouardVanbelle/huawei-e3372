#!/usr/bin/env python
# coding=utf-8
# vim: set fileencoding=utf-8 :

import sys
import pprint
import json

import argparse
import logging

import huawei.hilink
import huawei.hilinkHelper

# FIXME: need to dig into UTF8 and unicode problems :)

PAGINATION=20

# for python2 only:
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding("utf-8")

# -------------------------------------------------------------------------------------------------------


def browse( e3372):

    print( 'device phone number: {phone}'.format( phone=e3372.device_information().get("Msisdn")))

    print( 'Unread messages: {count}'.format( count=e3372.monitoring_check_notifications().get("UnreadMessage")))

    print( 'Total contacts: {count}'.format( count = e3372.sms_count_contact()))


    contact_index=1
    while True:

        contacts = e3372.sms_list_contact( page=contact_index, count=PAGINATION)


        for raw_contact in contacts:

            print

            if raw_contact['phone'] == None:
                print( "got a dirty entry, try to purge it")
                print( raw_contact)

                if raw_contact['index'] != 0:
                    try:
                        print( e3372.sms_delete_sms( [raw_contact['index']]))
                    except: 
                        print( "Unable to purge entry")

                continue

            # get first phone in contact
            phone=raw_contact["phone"]
            contact = huawei.hilinkHelper.Contact( phone, count=e3372.sms_count_contact( phone), driver=e3372)

            print( contact)

            message_index=1
            while True:

                messages = e3372.sms_list_phone(  phone, page=message_index, count=PAGINATION)

                for raw_message in messages:

                    message = huawei.hilinkHelper.Message( raw_message)
                    contact.append( message)


                if len( messages) < PAGINATION:
                    # no more messages
                    break

                message_index += 1

                if message_index > 100:
                    raise Exception("Too much iterations, please check system")


            # now we have all message for a given contact, print them, sorted by date

            for index in contact.sorted():

                message = contact.messages[index]
                print( message)


        if len(contacts) < PAGINATION:
            # no more contacts
            break

        contact_index += 1

        if contact_index > 100:
            raise Exception("Too much iterations, please check system")


# FIXME: enhance this code (currently crappy )
def flat_renderer( o, shift=""):
    
    if isinstance( o, dict):
        for key, value in o.items():
            if isinstance( value, dict) or isinstance( value, list):
                print( "{shift}{key}:".format( shift=shift, key=key))
                flat_renderer( value, "   "+shift)
            else:
                # force encoding with python2
                print( "{shift}{key}: {value}".format( shift=shift, key=key, value=value))
        print

    elif isinstance(o , list):
        for elem in o:
            flat_renderer( elem, "  "+shift)
        print

    else:
        print( "{shift}{value}".format( shift=shift, value= o))

def json_render( o):
    print( json.dumps( o))

def main():

    logging.basicConfig()

    parser = argparse.ArgumentParser() #prog='PROG')
    parser.add_argument('--host', default="192.168.8.1", help="IP address to query (default: %(default)s)")
    parser.add_argument('-v', '--verbose', action="count", help="verbose mode")
    parser.add_argument('-o', '--output',  default="flat", choices=['flat', 'json'], help="output format (default: %(default)s)")
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

    parser_sms_action_status = parser_sms_action.add_parser( 'status', help="sms status (informations)")
    parser_sms_action_send   = parser_sms_action.add_parser( 'send', help="send sms")
    parser_sms_action_send.add_argument( "--phone", required=True)
    parser_sms_action_send.add_argument( "--message", required=True)

    parser_sms_action_browse = parser_sms_action.add_parser( 'browse', help="browse contacts and messages")
    parser_sms_action_list   = parser_sms_action.add_parser( 'list', help="list message in a given box")
    parser_sms_action_list .add_argument( "--box", default=1, type=int, help="1:local-inbox 2:local-sent 3:local-draft 4:local-trash 5:sim-inbox 6:sim-sent 7:sim-draft 8:sim-trash") 

    parser_sms_action_contact  = parser_sms_action.add_parser( 'contact', help="get contacts and their last message")

    parser_sms_action_contact_message   = parser_sms_action.add_parser( 'list-by-phone', help="list message for a given contact (phone)")
    parser_sms_action_contact_message.add_argument( "--phone", required=True)

    parser_sms_action_mack   = parser_sms_action.add_parser( 'ack-message', help="acknowledge a message")
    parser_sms_action_mack.add_argument( "--id", type=int, required=True)

    parser_sms_action_mdel   = parser_sms_action.add_parser( 'del-message', help="delete a message")
    parser_sms_action_mdel.add_argument( "--id", type=int, required=True)

    parser_sms_action_mdel   = parser_sms_action.add_parser( 'retry-message', help="send a message (in draft)")
    parser_sms_action_mdel.add_argument( "--id", type=int, required=True)

    parser_sms_action_cdel   = parser_sms_action.add_parser( 'del-contact', help="delete a contact (and associated messages)")
    parser_sms_action_cdel.add_argument( "--phone", required=True)

    parser_api = subparser_section.add_parser('api', help='helper, direct API call (GET only)')
    parser_api.add_argument('--path', required=True)

    args = vars( parser.parse_args())

    if args['verbose'] != None:
        if args['verbose'] == 1:
            huawei.hilink.setLogLevel( logging.INFO)

        elif args['verbose'] > 1:
            huawei.hilink.setLogLevel( logging.DEBUG)

    # FIXME: choose correct renderer according choice
    render = flat_renderer
    if args["output"] == "json":
        render = json_render

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

            if args['action'] == 'provider':
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

            elif args['action'] == 'contact':
                index=1
                merged=[]
                while True:
                    answer=e3372.sms_list_contact( page=index, count=PAGINATION)
                    merged += answer
                    if len(answer) < PAGINATION:
                        break
                    index+=1
                    if index > 100:
                        raise Exception("Too much iterations, please check system")
                render( merged)

            elif args['action'] == 'list':
                index=1
                merged=[]
                while True:
                    answer=e3372.sms_list( boxtype=args['box'], page=index, count=PAGINATION)
                    merged += answer
                    if len(answer) < PAGINATION:
                        break
                    index+=1
                    if index > 100:
                        raise Exception("Too much iterations, please check system")
                render( merged)

            elif args['action'] == 'list-by-phone':
                index=1
                merged=[]
                while True:
                    answer=e3372.sms_list_phone(  args['phone'], page=index, count=PAGINATION)
                    merged += answer
                    if len(answer) < PAGINATION:
                        break
                    index+=1
                    if index > 100:
                        raise Exception("Too much iterations, please check system")
                render( merged)

            elif args['action'] == 'browse':
                #only case where json is not possible
                browse( e3372) 

            elif args['action'] == 'ack-message':
                render( e3372.sms_set_read( args['id']))

            elif args['action'] == 'del-message':
                render( e3372.sms_delete_sms( args['id']))

            elif args['action'] == 'del-contact':
                render( e3372.sms_delete_phone( args['phone']))
          
            elif args['action'] == 'retry-message':

                index=1
                found=None
                while True:
                    # read only in local-draft 
                    # FIXME: 'd better to use Enum to make more readable code
                    answer=e3372.sms_list( boxtype=3, page=index, count=PAGINATION)
                    for message in answer:
                        if int( message['Index']) == args['id']:
                            found=message
                            break

                    if len(answer) < PAGINATION or found!=None:
                        break
                    index+=1
                    if index > 100:
                        raise Exception("Too much iterations, please check system")

                if found == None:
                    raise huawei.hilink.ResponseException( 0, "Message not found in draft")

                #resend message
                render( e3372.send_sms( message["Phone"], message["Content"], index=args['id']))

        elif args['section'] == 'api':
            # ensure path starts with /api
            path = args['path']
            if path[0] != "/":
                path = "/"+path
            if path[:4] != "/api":
                path = "/api"+path
            render( e3372.get( path))

        else:
            print( "work in progress...")
            return

    except huawei.hilink.ResponseException as e:
        print( e)

if __name__ == "__main__":
    main()

