#!/usr/local/bin/python3
"""
Usage example : ./agg-hosts.py -t last_hour -v Google Amazon
"""
import argparse
import copy
import re
import pprint
import dateutil
import os
import json
import msiempy
import msiempy.event  # https://github.com/mfesiem/msiempy
from manuf import manuf  # https://github.com/coolbho3k/manuf

#Wi-Fi related signature ids
RADIUS_START='268-2239707159'
DHCP_NEW='272-10'
DHCP_RENEW='272-11'

TEMPLATE_ROW=dict(user='', host='', macaddress='', seen='', ip='')

def loadJsonDB(file):
    if not os.path.exists(file):
        templatedb=[]
        f=open(file, 'w')
        json.dump(templatedb, f)
        f.close()
    try :
        with open(file, 'r') as f :
            return json.load(f)
    except Exception as err:
        print("Failed to load the JSON database :"+str(err))
        exit()

def writeJsonDB(db, file):
    with open(file, 'w') as f :
        json.dump(db, f, indent=1)

def find(
    time_range,
    hostname_must_contains=[],
    hostname_must_not_contains=[],
    vendors=[],
    sig_ids=[],
    device_list_to_update=[]
    ):
    
    events = msiempy.event.EventManager(
        fields=[
            "SrcIP",
            "SrcMac",
            "HostID",
            "UserIDSrc",
            "DSIDSigID",
            "LastTime"],
        time_range=time_range,
        limit=1000
    )
    if sig_ids:
        events.add_filter(msiempy.event.FieldFilter('Alert.DSIDSigID', sig_ids))

    print('Loading data...')
    events.load_data(slots=10, workers=10, max_query_depth=5)
    print('{} events have been loaded from the SIEM'.format(len(events)))
    
    if len(vendors) > 0 :
        print('Filtering vendors...')
        mac = manuf.MacParser(manuf_name='manuf', update=True)
        vendor_filtered_events=list()

        for event in events : 

            device_vendor = mac.get_manuf(event['SrcMac'])
            
            if device_vendor == None:
                continue

            for vendor in vendors : 
                if vendor.lower() in device_vendor.lower() :
                    vendor_filtered_events.append(event)
                    break

        events = vendor_filtered_events
    print('{} events matches the vendor(s)'.format(len(events)))
    
    print('Aggregating events and devices...')
    devices=aggregate_list_based_on_SrcMac(events, device_list_to_update)
    print('{} unique devices in total in host list'.format(len(devices)))

    #Apply host filters
    host_filtered_devices=list()
    for dev in devices :
        if len(hostname_must_contains)==0 or any([ match.lower() in dev.get('host').lower() for match in hostname_must_contains ]):
            if len(hostname_must_not_contains)==0 or not any([ match.lower() in dev.get('host').lower() for match in hostname_must_not_contains ]):
                host_filtered_devices.append(dev)

    devices=host_filtered_devices
    print('{} devices matches hostname filter(s)'.format(len(devices)))

    return devices

def aggregate_list_based_on_SrcMac(event_list, device_list_to_update=[]):
    new_list=device_list_to_update

    devicesAdded=set()
    devicesUpdated=set()

    for event in event_list :
        found = False

        # print(event)

        for entry in new_list :
           
            #if the computer was already there in the database
            if entry['macaddress'] == event['Alert.SrcMac'] :
                found=True
                
                #Updates the last seen date and IP address
                #If the event is more recent that the last seen entry date
                if dateutil.parser.parse(event['Alert.LastTime']) > dateutil.parser.parse(entry['seen']):
                    
                    entry['seen']=event['Alert.LastTime']
                    entry['ip']=event['Alert.SrcIP']

                #if the hostname is not empty, the two hostnames are not equals and the event is a dhcp event
                if (len(event['HostID'])>0 and
                    entry['host'] != event['HostID'] and 
                    (event['Alert.DSIDSigID'] == DHCP_NEW or event['Alert.DSIDSigID'] == DHCP_RENEW)):

                    #Update the hostname
                    entry['host'] = event['HostID']
                
                #if the SIEM user field is not empty and the event is a radius login and the username is not already filled in the entry and the field is not a macaddress
                if (len(event['UserIDSrc'])>0 and 
                    event['Alert.DSIDSigID'] == RADIUS_START and 
                    entry['user'] != event['UserIDSrc'] and
                    re.match(r'''[0-9a-f]{2}([-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$''',event['UserIDSrc']) is None):

                    #Update the username
                    entry['user']=event['UserIDSrc']

                devicesUpdated.update([event['Alert.SrcMac']])

        if not found :
            entry=copy.copy(TEMPLATE_ROW)

            #we cannot trust the host infos from the radius events
            if event['Alert.DSIDSigID'] != RADIUS_START:
                entry['host']=event['HostID']

            #And we cannot trust the user info from the dhcp events. And sometime the user fields is a macaddress actually, so we ignore that
            elif event['Alert.DSIDSigID'] == RADIUS_START and not re.match(r'''[0-9a-f]{2}([-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$''', event['UserIDSrc']):
                entry['user']=event['UserIDSrc']

            entry['seen']= event['Alert.LastTime']
            entry['macaddress'] = event['Alert.SrcMac']
            entry['ip']=event['Alert.SrcIP']

            new_list.append(entry)

            devicesAdded.update(event['Alert.SrcMac'])

    print('{} devices were added'.format(len(devicesAdded)))    
    return new_list

def parse_args():

    parser = argparse.ArgumentParser(description='Create and automatically maintain a list of hosts records based on filters by querying McAfee SIEM logs.')
    parser.add_argument('-l', '--hostlist', metavar='File path', help='Host list JSON file', default='hosts.json')
    parser.add_argument('-t', '--timerange', metavar='Time range', help='SIEM time range to analyse. For example LAST_3_DAYS.', default='last_24_hours')
    parser.add_argument('-m', '--hostname_must_contains', metavar='Hostname match', nargs='+', default=[])
    parser.add_argument('-n', '--hostname_must_not_contains', metavar='Hostname match', nargs='+', default=[])
    parser.add_argument('-v', '--vendors', metavar='Vendor match', nargs='+', default=[])
    parser.add_argument('-s', '--sigids', metavar='SigID', help='Signature IDs to consider in the search. Leave None to consider all SigIDs.', nargs='+', default=None)

    args = parser.parse_args()

    return args

#   MAIN PROGRAM
if __name__ == "__main__":
    args = parse_args()

    print(args)

    hostlist = loadJsonDB(args.hostlist)

    devices=find(time_range=args.timerange, 
        hostname_must_contains=args.hostname_must_contains, 
        hostname_must_not_contains=args.hostname_must_not_contains, 
        vendors=args.vendors,
        sig_ids=args.sigids, 
        device_list_to_update=hostlist)

    writeJsonDB(hostlist, args.hostlist)

    print(msiempy.NitroList(devices).get_text())