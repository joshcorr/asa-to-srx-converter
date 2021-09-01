#! /usr/bin/python3 python3.9.5

"""
Script for converting some of an ASA configuration to JUNOS set commands for the SRX

"""
# Josh Corrick

# Generic/Built-in
import argparse
import ipaddress
import re
import csv
import logging
from ipaddress import IPv4Address, IPv4Network, ip_network
from socket import getservbyname
from hashlib import sha1

__author__ = "Josh Corrick"
__copyright__ = "Copyright 2021, Josh Corrick"
__credits__ = ["Josh Corrick"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Josh Corrick"


parser = argparse.ArgumentParser()
parser.add_argument("inputFile", help="/full/path/to/file")
parser.add_argument("outputFile", help='''
    /path/to/outputfile
    WARNING will overwrite the file
    ''')
parser.add_argument("-zo", "--zoneOverrides", help='''
    /path/to/zoneOverrides.csv
    Provide the zone to network map
    Should have the headers interface and zone
    Below is an example of what it should look like:
        zone,network
        default_zone,0.0.0.0/0
    ''',
                    default=None)
parser.add_argument(
    "--passthrough", action="store_true", help="writes the content to output instead of a file")
parser.add_argument(
    "--log",
    default="warning",
    help=(
        "Provide logging level."
        "Example --log info, default='warning'"
    )
)
parser.add_argument("-lf", "--logFile", help='''
    /path/to/file.log
    Provide the path for the logfile
    If not provided the log streams to STDOUT
    ''',
                    default=None)
args = parser.parse_args()
levels = {
    'critical': logging.CRITICAL,
    'error': logging.ERROR,
    'warn': logging.WARNING,
    'warning': logging.WARNING,
    'info': logging.INFO,
    'information': logging.INFO,
    'debug': logging.DEBUG
}
level = levels.get(args.log.lower())

if args.logFile:
    logging.basicConfig(filename=args.logFile, filemode='a',
                        format='%(levelname)s:%(message)s', level=level)
else:
    logging.basicConfig(format='%(levelname)s:%(message)s', level=level)

with open(args.inputFile, "r") as configFile:
    config = configFile.read()

# Various lists and dictionaries used for data lookup
# way to track which lines haven't been handled
configRemaining = re.split(r'\n', config)
output = []  # data eventually written out
overrideInterfaces = []  # overrides provided from
originalInterfaces = []  # original port and route interfaces from cisco
addressBook = []  # lookup list for name to ip resolution
accessGroups = {}  # access-group lookup dictionary
aclData = {}  # nested dictionary containing acl data
addressGroups = []  # lookup list for object-group items that don't have an ip
serviceList = [] # lookup for Service

# if a zone override is provided to the script
if args.zoneOverrides:
    with open(args.zoneOverrides, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            zone = row['zone']
            network = row['network']
            overrideInterfaces.append({zone: network})

# Custom Functions


def ip_in_prefix(ip, network):
    """Tests an IP against a network"""
    logging.debug(f'Ip is {ip}; Network is:{network}')
    value = ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(network)
    return value


def test_ip(ip):
    """Used to test an IP, but supress the error with a bool"""
    try:
        return ipaddress.IPv4Address(ip)
    except:
        return False


def lookup_zone(ip, interfaces):
    """Looks up a zone by IP address and returns a string"""
    zone = 'UNKNOWN'
    for inf in interfaces:
        # in case the interfaces is a list of dicts
        if isinstance(inf, dict):
            for listinf in inf:
                if ip_in_prefix(ip, inf[listinf]):
                    zone = listinf
        # default when a dictionary is passed
        elif ip_in_prefix(ip, interfaces[inf]):
            zone = inf
    if zone == 'UNKNOWN':
        logging.warning(f'No zone found for {ip}')
    return zone


def lookup_zone_by_name(name, interfaces):
    """Looks for a network by name and returns a list"""
    zone = []
    for inf in interfaces:
        if isinstance(inf, dict):
            for listinf in inf:
                if name in listinf:
                    zone.append({listinf: inf[listinf]})
        elif name in inf:
            zone.append({inf: interfaces[inf]})
    return zone


def lookup_address_item(item, addressBook, itemType):
    """Repeatable way to lookup a name, ip, or zone from the addressBook"""
    itemIndex = {
        'all': -1,
        'name': 0,
        'ip': 1,
        'zone': 2,
    }
    i = itemIndex[itemType]
    if test_ip(item):
        r = re.compile(f'.+:{item}:.+')
    else:
        r = re.compile(f'{item}:.+')
    addressItem = list(filter(r.match, addressBook))
    if len(addressItem) == 0:
        info = []
        logging.warning(f'Unable to find an address book entry for: {item}')
    else:
        if i == -1:
            info = [a for a in addressItem]
        else:
            info = [a.split(':')[i] for a in addressItem]
    if len(info) != 1:
        # find unique items in the list
        info = list(set(info))
    if len(info) == 1:
        # return a string if only one item is found
        info = info[0]
    return info


def remove_line_from_config(object, list):
    """Removes an item from a list of remaining config"""
    for i in object.split('\n'):
        try:
            list.remove(i)
        except:
            logging.debug(f'issues with {i}')


def resolve_portnumber(service):
    """Uses getservbyname from the socket module to resolve port numbers"""
    if re.match(r'[^\d]', service):
        logging.debug(f'Grabbing the numeric version of {service}')
        try:
            port = getservbyname(service)
        except:
            if service == 'rsh':
                port = 514
            else:
                logging.error(f'Unknown port number for {service}')
    else:
        port = service
    return port


def get_unique_acl_hash(from_zone, to_zone, destination_addressbook_name, source_addressbook_name):
    """Uses hashlib to calcualte a unique sha1 for unique elements of an ACL"""
    hash = sha1(bytes(
        f"{from_zone} + {to_zone} + {source_addressbook_name} + {destination_addressbook_name}", 'utf-8')).hexdigest()
    return hash


def get_override_from_zone(originalZones, overrideInterfaces, failback_address, addressBook):
    """Determines the correct override zone from the original ACL and destination addresses"""
    zone = "UNKNOWN"
    failback_source_address = lookup_address_item(failback_address, addressBook, 'ip')
    if len(originalZones) == 1:
        network = ''.join(originalZones[0].values()).split('/')[0]
        zone = lookup_zone(network, overrideInterfaces)
    elif failback_source_address:
        # Use the source as the next best lookup if multiple original zones
        zone = lookup_zone(failback_source_address, overrideInterfaces)
    else:
        # loop over the zones only if we have to
        for x in originalZones:
            network = ''.join(x.values()).split('/')[0]
            testZone = lookup_zone(network, overrideInterfaces)
            if testZone:
                zone = testZone
    return zone


logging.info('Creating the banner')
bannerQuery = re.compile(r'(^banner\s.+\n)')
banner = re.findall(bannerQuery.pattern, config, re.MULTILINE)
banInfo = [] # a list to hold the banners
for ban in banner:
    banInfo.append(re.split(r'^banner\s\b(login|asdm)\b\s',ban.rstrip()))
    remove_line_from_config(ban, configRemaining)

for banType in ('login','asdm'):
    banString = '\\n'.join([x[2] for x in banInfo if x[1] == banType])
    if banType == 'adsm':
        banType = 'telnet'
    message = f"set admin auth banner console {banType} '{banString}'"
    output.append(message)

# Creates the Zones from ASA Interfaces
logging.info('Setting zones from physical interfaces')
interfaceQuery = re.compile(
    r'(^interface .+\n((.+\n){1,2}|(.+\n){3,4}|(.+\n){5,6}))\!$')
interface = re.findall(interfaceQuery.pattern, config, re.MULTILINE)

# iterate over the physical interfaces
for int in interface:
    if re.search(r'no ip address', int[0]) or not re.search(r'ip address', int[0]):
        logging.warning(f'bypassing {int[0]}')
    else:
        # find interface name and split it. This is the Zone.
        try:
            ifname = re.findall(r'(?=nameif\s).+[^\n]', int[0])
            ifname = ifname[0].split(' ')[-1]
        except:
            logging.warning(f'bypassing {int[0]}')
            continue
        # find ip address data and split it up
        ipData = re.findall(r'(?=ip address\s).+[^\n]', int[0])
        ipDataList = ipData[0].split(' ')
        gateway = ipDataList[2]
        subnetIP = ipDataList[3]
        tempAddress = f'{gateway}/{subnetIP}'
        # need the network for later comparisons
        network = ipaddress.ip_network(tempAddress, strict=False)
        netmask = network.prefixlen
        # create a list of the devices original interfaces
        originalInterfaces.append({ifname: network.with_prefixlen})

        # if there is an override we create the new reth here.
        if overrideInterfaces:
            ifname = lookup_zone(gateway, overrideInterfaces)

        logging.debug(ifname)
        message = f'set security zones security-zone {ifname} interfaces reth#.####'
        output.append(message)
    remove_line_from_config(int[0], configRemaining)


# Routes provide another location of networks for zones
logging.info('Looking through route table for zones')
routeQuery = re.compile(r'^route .+')
route = re.findall(routeQuery.pattern, config, re.MULTILINE)

for path in route:
    routeSplit = path.split(' ')
    routeName = routeSplit[1]
    subnet = routeSplit[2]
    netmask = routeSplit[3]
    network = ipaddress.ip_network(f'{subnet}/{netmask}', strict=False)
    logging.debug(network)
    originalInterfaces.append({routeName: network.with_prefixlen})
    remove_line_from_config(path, configRemaining)

# sets the interfaces/zones to be used for ip lookup
if overrideInterfaces:
    interfaces = overrideInterfaces
else:
    interfaces = originalInterfaces


# Address-Book
logging.info('Setting addresses in address-book')
addressQuery = re.compile(r'^object network.+\n.+\d$')
address = re.findall(addressQuery.pattern, config, re.MULTILINE)

for add in address:
    split = re.split(r'\s', add)
    name = split[2]
    ip = split[5]
    if re.search(r'nat', add):
        logging.info(f'not processing: {add}')
        remove_line_from_config(add, configRemaining)
        continue
    else:
        zone = lookup_zone(ip, interfaces)
    if re.search(r'subnet', add):
        # the 6th item in the split is the subnet
        tempAddress = f'{ip}/{split[6]}'
        netmask = IPv4Network(tempAddress).prefixlen
        message = f'set security zones security-zone {zone} address-book address {name} {ip}/{netmask}'
        addressBook.append(f'{name}:{ip}:{zone}')
    else:
        message = f'set security zones security-zone {zone} address-book address {name} {ip}/32'
        addressBook.append(f'{name}:{ip}:{zone}')
    output.append(message)
    remove_line_from_config(add, configRemaining)


# Add missing address for ACL creation later
logging.info('Creating missing address in the address-book')
addressSetQuery = re.compile(r'(^object-group network.+\n( network-.+\n)*)')
addressSet = re.findall(addressSetQuery.pattern, config, re.MULTILINE)

for addSet in addressSet:
    network = re.findall(r'(?=network-object\s).+[^\n]', addSet[0])
    for net in network:
        currentNet = net.split(' ')[-1]
        addressBookEntry = lookup_address_item(currentNet, addressBook, 'all')

        # needed to create an address book entry so Address-Sets can be made if no network-objects exist
        if not addressBookEntry and test_ip(currentNet):
            zone = lookup_zone(currentNet, interfaces)
            name = f"{zone}_{currentNet}"
            addressBook.append(f'{name}:{currentNet}:{zone}')
            message = f'set security zones security-zone {zone} address-book address {name} {currentNet}/32'
            output.append(message)


# Address-set
logging.info('Creating the address-set')
# using same query as last section
for addSet in addressSet:
    group = re.findall(r'(?=object-group\s).+[^\n]', addSet[0])
    group = group[0].split(' ')[-1]

    network = re.findall(r'(?=network-object\s).+[^\n]', addSet[0])
    for net in network:
        currentSetAddr = currentNet = net.split(' ')[-1]
        logging.debug(f'Current Address: {currentNet}')
        addressBookEntry = lookup_address_item(currentNet, addressBook, 'all')

        if not addressBookEntry:
            continue

        address_name = lookup_address_item(currentNet, addressBook, 'name')

        if not test_ip(currentNet):
            currentSetAddr = lookup_address_item(currentNet, addressBook, 'ip')

        zone = lookup_zone(currentSetAddr, interfaces)
        message = f'set security zones security-zone {zone} address-book address-set {group} address {address_name}'
        addressGroups.append(f"{group}:NOIP:{zone}")
        output.append(message)
    remove_line_from_config(addSet[0], configRemaining)


# Object Service conversion to Application Set
logging.info('Creating applications from object service')
objectServiceSetQuery = re.compile(r'^object service.+\n.+$')
objectServiceSet = re.findall(
    objectServiceSetQuery.pattern, config, re.MULTILINE)

for objSet in objectServiceSet:
    split = re.split(r'\s', objSet.rstrip())
    split.remove('')
    destination = ''
    group = split[2]
    protocol = split[4]
    direction = split[5]
    argumentType = split[6]

    if argumentType == 'eq':
        port = resolve_portnumber(split[-1])
    elif argumentType == 'range':
        port = f'{resolve_portnumber(split[-2])}-{resolve_portnumber(split[-1])}'
    else:
        logging.warning(f'Not sure what to do with {argumentType}')
        port = ''

    if direction != 'source':
        message = f'set applications application {group} term 1 protocol {protocol}\nset applications application {group} term 1 destination-port {port}'
    else:
        message = f'set applications application {group} term 1 protocol {protocol}\nset applications application {group} term 1 source-port {port}'
    output.append(message)
    remove_line_from_config(objSet, configRemaining)


# Applications are setup here
logging.info('Creating the applications from object-group service')
serviceSetQuery = re.compile(r'(^object-group service.+\n( service-.+\n)*)')
serviceSet = re.findall(serviceSetQuery.pattern, config, re.MULTILINE)

for servSet in serviceSet:
    group = re.findall(r'(?=object-group\s).+[^\n]', servSet[0])
    group = group[0].split(' ')[-1]

    currentServiceSet = [] #list to hold applications for evaluating application-sets
    service = re.findall(r'(?=service-object\s).+[^\n]', servSet[0])
    for (s, serv) in enumerate(service, start=1):
        message = ''
        destination = ''

        try:
            split = serv.rstrip().split(' ')
            currentProtocol = split[1]
            argumentType = split[3]
        except:
            logging.error(f'Error processing {serv}')
            continue

        if argumentType == 'eq':
            logging.debug(f'trying po')
            destination = resolve_portnumber(split[-1])
        elif argumentType == 'range':
            destination = f'{resolve_portnumber(split[-2])}-{resolve_portnumber(split[-1])}'
        else:
            logging.error(f'Not sure what to do with {argumentType}')
            continue
        currentServiceSet.append({currentProtocol:destination})

    # variables for the following loops
    applicationSet = True if len(currentServiceSet) > 8 else False
    termNumber = 0 # each application needs a term
    groupNumber = 1 # if more than 8 terms we need multiple application sets
    currentGroupSet = [] # list of multiple groups

    for serviceSet in currentServiceSet:
        protocol, dest = list(serviceSet.items())[0]
        # Max Term is 8
        if applicationSet and termNumber == 8:
            termNumber = 0
            groupNumber += 1
        applicationGroup = f"{group}_{groupNumber}" if applicationSet else f"{group}"
        termNumber += 1
        currentGroupSet.append(applicationGroup)
        # instead of outputing we should capture and create at once
        message = f'set applications application {applicationGroup} term {termNumber} protocol {protocol}\nset applications application {applicationGroup} term {termNumber} destination-port {dest}'
        output.append(message)

    if applicationSet:
        for groupSet in sorted(set(currentGroupSet)):
            message = f'set applications application-set {group} application {groupSet}'
            output.append(message)

    remove_line_from_config(servSet[0], configRemaining)

# need to split applications (and create application sets) max term is 8!

# Create Policies
logging.info('Creating the polices from access-list and access-group')
accessGroup = re.findall(r'(^access-group.+)', config, re.MULTILINE)
for grp in accessGroup:
    split = re.split(r'\s', grp)
    group_name = split[1]
    # grabbing the access group direction:interface for future lookup (not used yet)
    # this would map the access-list <NAME> to an interface
    accessGroups[group_name] = f'{split[2]}:{split[-1]}'
    remove_line_from_config(grp, configRemaining)

accessList = re.findall(r'^access-list.+\n', config, re.MULTILINE)
for acl in accessList:
    if re.search(r' deny ', acl):
        # Because of implicit junos deny
        logging.warning(f'Not creating acl for deny: {acl}')
        remove_line_from_config(acl, configRemaining)
        continue

    if re.search(r'any any', acl):
        logging.warning(f'Not sure what to do with permit any: {acl}')
        remove_line_from_config(acl, configRemaining)
        continue

    try:
        split = re.split(r'\s', acl.rstrip())

        # an acl may be written in acouple of different ways
        # either with an "eq ssh" at the end
        # or earlier in the ACL as an OBJECT
        if split[-2] == 'eq' and resolve_portnumber(split[-1]):
            source_addressbook_name = split[-5]
            destination_addressbook_name = split[-3]
            application_name = f"{split[5]}_{split[-1]}"
        else:
            source_addressbook_name = split[-3]  # 3rd item from end of acl
            destination_addressbook_name = split[-1]  # last item at end of acl
            application_name = split[5]

        if overrideInterfaces:
            # find the networks associated with the original interface
            originalZones = lookup_zone_by_name(split[1], originalInterfaces)
            # if only one then match to override networks
            # if multiple check source_addressbook_name to try to determine the network
            from_zone = get_override_from_zone(
                originalZones, overrideInterfaces, source_addressbook_name, addressBook)
        else:
            from_zone = split[1]  # technically the interface
        # r = re.compile(f'{destination_addressbook_name}:.*')
        # addressBookEntry = list(filter(r.match, addressBook))
        currentToAddress = lookup_address_item(
            destination_addressbook_name, addressBook, 'ip')
        group = lookup_address_item(
            destination_addressbook_name, addressGroups, 'zone')
    except:
        # addressbook Entry creation needed
        logging.error(f'Issue processing ACL: {acl}')
        continue

    if currentToAddress:
        to_zone = lookup_zone(currentToAddress, interfaces)
        if to_zone == 'UNKNOWN':
            logging.warning(f'No zone found for {currentToAddress}')
    elif group:
        to_zone = group[0]
        if to_zone == 'UNKNOWN':
            logging.warning(f'No zone found for {currentToAddress}')
    else:
        logging.warning(f'Not enough informartion to create ACL on: {acl}')
        continue
    # generate a unique id for the ACL by creating a SHA1 of the source and destination
    uniqueACL = get_unique_acl_hash(
        from_zone, to_zone, destination_addressbook_name, source_addressbook_name)
    # if the unique id is already in aclData append the application
    if uniqueACL in aclData:
        aclData[uniqueACL]['application_name'].append(application_name)
    else:
        aclData[uniqueACL] = {'from_zone': from_zone, 'to_zone': to_zone, 'source_addressbook_name': source_addressbook_name,
                              'destination_addressbook_name': destination_addressbook_name, 'application_name': [application_name]}
    remove_line_from_config(acl, configRemaining)

for ace in aclData:
    finalAce = aclData[ace]
    policy_name = '_'.join(
        finalAce['application_name'])+'_'+(finalAce['source_addressbook_name'])

    # policy start and end should always be the same.
    policy_start = f"""set security policies from-zone {finalAce['from_zone']} to-zone {finalAce['to_zone']} policy {policy_name} match source-address {finalAce['source_addressbook_name']}
set security policies from-zone {finalAce['from_zone']} to-zone {finalAce['to_zone']} policy {policy_name} match destination-address {finalAce['destination_addressbook_name']}\n"""
    policy_end = f"""set security policies from-zone {finalAce['from_zone']} to-zone {finalAce['to_zone']} policy {policy_name} then permit
set security policies from-zone {finalAce['from_zone']} to-zone {finalAce['to_zone']} policy {policy_name} then log session-init
set security policies from-zone {finalAce['from_zone']} to-zone {finalAce['to_zone']} policy {policy_name} then log session-close"""
    # Policy Application may very in length
    policy_application = ''
    for app in finalAce['application_name']:
        policy_application += f"set security policies from-zone {finalAce['from_zone']} to-zone {finalAce['to_zone']} policy {policy_name} match application {app}\n"

    message = f"{policy_start}{policy_application}{policy_end}"
    output.append(message)

# Explicitly unhandled lines of config
logging.info(
    'Looking for lines explicitly not handled by this script: nat, crypto ca, !')
nat = re.findall(r'(^nat.+)', config, re.MULTILINE)
for n in nat:
    logging.debug(f"not processing nat: {n}")
    remove_line_from_config(n, configRemaining)

ca = re.findall(r'(?sm)^crypto\sca.*(?=quit)', config, re.MULTILINE)
for c in ca:
    logging.debug(f"not processing ca: {c}")
    remove_line_from_config(c, configRemaining)

ticks = re.findall(r'(^!|^:)',config, re.MULTILINE)
for t in ticks:
    logging.debug(f"not processing marks: {t}")
    remove_line_from_config(t, configRemaining)


logging.info(f'Only {len(configRemaining)} lines unprocessed by this script')
configString = "\n".join(str(x) for x in configRemaining)
logging.info(configString)

if args.passthrough:
    logging.info('Output to console if --passthrough')
    for out in output:
        print(out)
# Write the content to the a file
else:
    with open(args.outputFile, mode='wt', encoding='utf-8') as newConfigFile:
        for out in output:
            newConfigFile.writelines(out)
            newConfigFile.writelines('\n')
