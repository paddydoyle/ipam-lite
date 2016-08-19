#!/usr/bin/python

import smtplib
import re
import sys
import subprocess
import ConfigParser
from datetime import date
import argparse
from netaddr import EUI
from netaddr import core
from netaddr import IPNetwork
from netaddr import mac_unix
import pprint
import socket



####################################################
# vars
####################################################

config_file    = 'config.ini'
#data_file      = 'data.ini'
arp_file       = 'arp/arp.dat'
dhcp_file      = 'dhcp/dhcpd.conf'

####################################################



####################################################
# read the filenames from cmd-line
####################################################

parser = argparse.ArgumentParser()
#parser.add_argument("address_file", help="CSV file containing the list of names and addresses")
#parser.add_argument("message_file", help="text file (with tokens) containing the email body text")
parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")
#parser.add_argument("-d", "--dpgt", help="specify that the mails are to be addressed to DPGT",
#                    action="store_true")
#parser.add_argument("-s", "--subject", help="parse the config.ini file only, print the subject line, and exit",
#                    action="store_true")
args = parser.parse_args()

if args.verbose:
   print "verbosity turned on"

#if args.dpgt:
#   #print "dpgt turned on"
#   same_recipient = 'Director of Postgraduate Teaching'
#else:
#    same_recipient = None


#if (len(sys.argv) == 4):
#    if (sys.argv[3] == "-d"):
#        same_recipient = 'Director of Postgraduate Teaching'
#    else:
#        print "usage: " + sys.argv[0] + " address_file message_file [-d]"
#        sys.exit()
#
#if (len(sys.argv) == 3 or len(sys.argv) == 4):
#    address_file = sys.argv[1]
#    message_file = sys.argv[2]
#else:
#    print "usage: " + sys.argv[0] + " address_file message_file [-d]"
#    sys.exit()

#print "address_file is " + address_file
#print "message_file is " + message_file
#print "same_recipient is " + same_recipient




####################################################
# main
####################################################
def main():
    # list of error messages
    error_list = []

    # read the config file
    config = parse_config()

    # read the arp entries
    arp_entries = parse_arp_file(arp_file, error_list)

    # read the dhcp entries
    dhcp_entries = parse_dhcp_file(dhcp_file, error_list)

    # loop
    main_report(config, arp_entries, dhcp_entries, error_list)

#    tpl = read_addrs(args.address_file)
#
#    if tpl:
#
#        mail_list(smtpserver ,fromaddr, replyto, config.get('Subject', 'subject'), tpl, smsg)
#        print
#        print
#    else:
#        print 'Error: cannot find emails in file'

    if len(error_list):
        display_errors(error_list)


def main_report(config, arp_entries, dhcp_entries, error_list):
    'loop over all of the addresses in the range'

    net = IPNetwork(config.get('Network', 'v4address') + '/' + config.get('Network', 'v4mask'))

    reverse_lookups = {}
    forward_lookups = {}

    for ip in net.iter_hosts():
        ip = str(ip)

        if args.verbose:
            print '%s' % ip

        host = ''
        resolved_ip = ''

        # look up the hostname
        try:
            res = socket.gethostbyaddr( ip )

            if args.verbose:
                print "found" + str(res)

            host = res[0]
            reverse_lookups[ip] = host

        except socket.error:
            if args.verbose:
                print "unable to reverse look up " + ip

        # now resolve the IP
        if host:
            try:
                resolved_ip = socket.gethostbyname(host)

                forward_lookups[host] = resolved_ip
            except socket.error:
                print "unable to forward look up " + host
                resolved_ip = record_error(error_list, "unable to forward look up " + host)

        if resolved_ip and ip != resolved_ip:
            print "warning: " + ip + " != " + resolved_ip

    #print "\nall forward lookups:\n"
    #for host in forward_lookups:
    #    print '  {0:20} ==> {1:20}'.format(host, forward_lookups[host])

    #for ip in reverse_lookups:
    #    print '  {0:20} ==> {1:20}'.format(ip, reverse_lookups[ip])

    # TODO: split the function here? create a dict of dicts of the entries?


    print "\nall records:\n"

# IP -> host -> IP (match y/n) -> MAC (DHCP) -> MAC (ARP) -> timestamp (ARP)
    format_str = '  {0:16} | {1:30} | {2:8} | {3:18} | {4:18} | {5}'
    print format_str.format('IP', 'Host', 'Host->IP', 'MAC (DHCP)', 'MAC (ARP)', 'Last seen (ARP)')
    print
    for ip in net.iter_hosts():
        ip = str(ip)

        # did we have a hostname?
        if not ip in reverse_lookups:
            host = '-'
            resolved_ip = '-'
        else:
            host = reverse_lookups[ip]

        if not host in forward_lookups:
            resolved_ip = '-'
        else:
            resolved_ip = forward_lookups[host]

        # does the hostname resolve back to the same IP?
        if ip == resolved_ip:
            resolved_ip = 'OK'
        elif host == '-':
            resolved_ip = '-'
        else:
            resolved_ip = record_error(error_list, 'forward and reverse lookup mismatch for ' + ip + ' => ' + host + ' => ' + resolved_ip)

        # do we have a hostname in the dhcp entries? first change to short hostname
        if host != '-' and host.endswith(config.get('Network', 'domain')):
            short_host = host[:-len(config.get('Network', 'v4address'))]

            if short_host in dhcp_entries:
                mac_dhcp = dhcp_entries[short_host]
            else:
                mac_dhcp = '-'

        else:
            short_host = '-'
            mac_dhcp = '-'

        # do we have an entry in arp?
        if ip in arp_entries:
            mac_arp  = arp_entries[ip]['mac']
            host_arp = arp_entries[ip]['host']
            ts_arp   = arp_entries[ip]['ts']
        else:
            mac_arp  = '-'
            host_arp = '-'
            ts_arp   = '-'

        #print '  {0:16} | {1:30} | {2:4}'.format(ip, host, resolved_ip)
        print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)


def create_mail(fromaddr, replyto, subject, name, addr, msg):
    'prefixes header info to email'

    prefix = 'From: '+fromaddr+'\r\nTo: '+addr+'\r\n'
    # add the date header for newer mailer systems
    prefix += 'Date: '+stupid_python_hack_get_date_rfc822()+'\r\n'
    prefix +=  'Reply-To: '+replyto+'\r\n'
    prefix += 'Subject: '+subject + '\r\n\r\n'
    send_name = name
    if same_recipient:
        send_name = same_recipient
    prefix += 'Dear '+send_name+',\n\n'
    prefix    += msg
    return prefix

def read_addrs(fname):
    'Reads in list of email addresses'

    tpl = {}
    try:
        f = open(fname,'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    print "Reading emails from " + fname + ":"

#  strip blank lines on read
    addr_list = []
    tpl       = {}
    for fline in f:
        fline = fline.strip()
        if re.match('^$',fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#',fline):
            #print 'skipped a comment line'
            continue
        addr_list.append(fline.split(','))

    for aa in addr_list:
        addr = aa[1].strip('"').strip()
        name = aa[2].strip('"').strip()
        if (re.match(email_match,addr)):
            if (name != ''):
                #print 'adding key/value: '+addr+'/'+name+' to hash'
                #print '    '+name+'\t('+addr+')'
                print '  {0:20} ==> {1:20}'.format(name, addr)
                tpl[addr] = name
            else:
                print 'skipping key/value: '+addr+'/'+name+' to hash'
        else:
            print 'Address: '+addr+'(for '+name+')'+\
                'does not appear to be an email  address'

    f.close()

    return tpl


def write_message_file(fname, msg):
    'Writes the message text to a file'

    # open the file
    try:
        f = open(fname,'w')
    except IOError, reason:
        print 'could not open file ' + fname, str(reason)
        return False

    # write the string
    try:
        f.write(msg)
    except IOError, reason:
        print 'could not open file ' + fname, str(reason)
        return False

    f.close()

    return True


def mail_list(smtpserver,fromaddr, replyto, subject, tpl, msg):
    'Send the emails'

    print '\nGetting ready to email...\n'
    
## have to do this because I potentially set really_send somewhere
## else in this function => confusion between local & global context
    global really_send

    if really_send:
        yesno = raw_input('Really send emails? ')
        if yesno != 'y':
            really_send = False

    try:
        server=smtplib.SMTP(smtpserver)
    except smtplib.SMTPException, diag:
        print 'Connection to SMTP server failed: '+diag
        return

    #print 'Server up...\n\n',
    server.set_debuglevel(smtp_debuglvl)

    if really_send:
        #print 'Sending emails...\n\n'
        sys.stdout.write('\nSending emails: ')
    else:
        #print 'NOT sending emails...\n\n'
        sys.stdout.write('\nNOT sending emails: ')

    if args.verbose:
        print
    
    for addr in tpl:
        if addr:
            name = tpl[addr]
            #print 'spamming '+name+' ('+addr+')'
            emsg = create_mail(fromaddr, replyto, subject, name, addr, msg)
            if args.verbose:
                print '-'*60
                print '>>>>> emailing: '+name+' ('+addr+')'
                print '-'*60
                print emsg
                print '-'*60
                print

            if really_send:
                server.sendmail(fromaddr, addr, emsg)
                #print '-'*60 +'mail sent!'
            #else:
                #print '-'*60 +'dummy send'
                #sys.stdout.write('.')

            if not args.verbose:
                sys.stdout.write('.')
        else:
            continue

    #print '\nsent'

    server.quit()
    #print '...Server down'
    print ' [DONE]'


# stupid function to return a date in RFC 2822 format
# (stupid because Python doesn't give you a timezone object by
# default -- you'd have to write your own class to get one!)
# otherwise we'd just create a datetime object and use strftime("%z")
def stupid_python_hack_get_date_rfc822():
    'Return a date in RFC 2822 format'

    p = subprocess.Popen(['date', '-R'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    out = out.rstrip()
    return out


# http://stackoverflow.com/a/21668902
# see also module 'inflect', but that's not installed on SL6
def ordinal(n):
    'Return the ordinal suffix for a number; 1->st; 2->nd; 3->rd; 4->th etc'

    if 10 <= n % 100 < 20:
        return str(n) + 'th'
    else:
       return  str(n) + {1 : 'st', 2 : 'nd', 3 : 'rd'}.get(n % 10, "th")


# Parse the config
def parse_config():
    'Parse the config file'

    config = ConfigParser.RawConfigParser()
    config.read(config_file)


    if args.verbose:
        print "config:\n"
        for section in config.sections():
            print "section name: " + section
            print config.items(section)

#    date_arr = map(int, config.get('Date', 'date').split('-'))
#    date1 = date(date_arr[0], date_arr[1], date_arr[2])
#
#    date2 = date1.strftime('%A ') + ordinal(date_arr[2]) + date1.strftime(' %B')
#    #print date2
#    date3 = date1.strftime('%B %Y')
#    #print date3
#
#    # what kind of mailing?
#    if message_file.startswith('workshop'):
#        subject = config.get('Subject', 'workshop-subject').replace('@date2@', date2).replace('@time@', config.get('Date', 'time'))
#    elif message_file.startswith('training'):
#        subject = config.get('Subject', 'training-subject').replace('@date3@', date3)
#    else:
#        print sys.argv[0] + ": error: unknown message_file type: " + message_file + ". Exiting."
#        sys.exit(1)
#
#    # save them to the config object for use later
#    config.set('Subject', 'subject', subject)
#    config.set('Date', 'date2', date1.strftime('%A ') + ordinal(date_arr[2]) + date1.strftime(' %B'))
#    config.set('Date', 'date3', date1.strftime('%B %Y'))
#
#    print '='*70
#    print "Subject: " + config.get('Subject', 'subject')
#    print '='*70
#    print

    return config


# Parse the dhcpd.conf file
def parse_dhcp_file(dhcp_file, error_list):
    'Parse the dhcpd.conf file'

    # TODO: exclude blank lines and comments
    dhcp_entries = {}

    try:
        f = open(dhcp_file,'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading dhcp file " + dhcp_file

    for fline in f:
        fline = fline.strip()
        if re.match('^$',fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#',fline):
            #print 'skipped a comment line'
            continue

        # try match the main regex
        # host tcin01 { hardware ethernet 00:30:48:7c:9b:ee;
        #matched = re.match('^\s*host\s+(\S+) \{\s*hardware\s*ethernet\s*(\S+)',fline)
        matched = re.match('^\s*host\s+(\S+) \{\s*hardware\s*ethernet\s*([0-9a-fA-F:]+)',fline)

        if matched:
            host = matched.group(1)
            mac  = canonicalise_mac(matched.group(2))

            dhcp_entries[host] = mac;

            if args.verbose:
                print "%s => %s" % (host, mac)

    f.close()

    #for e in dhcp_entries:
    #    print e + " => " + str(dhcp_entries[e])

    return dhcp_entries


# Parse the arp.dat file
def parse_arp_file(arp_file, error_list):
    'Parse the arp.dat file'

    arp_entries = {}
    try:
        f = open(arp_file,'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading arp file " + arp_file

    for fline in f:
        fline = fline.strip()
        if re.match('^$',fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#',fline):
            #print 'skipped a comment line'
            continue

        #addr_list.append(fline.split(','))
        # 2:0:ac:10:1:f 134.226.115.150 1444404183  dri-guest020
        entry_list = fline.split()

        if args.verbose:
            print '%s' % entry_list

        arp_entries[entry_list[1]] = {
            'mac': canonicalise_mac(entry_list[0]),
            'ts': entry_list[2],
            'host': entry_list[3] if len(entry_list) > 3 else '',
        }

    f.close()

    #for e in arp_entries:
    #    print e + " => " + str(arp_entries[e])

    return arp_entries


def record_error(error_list, message):
    'Store the error string, and return the index into the error array'
    error_list.append(message)
    return 'ERR' + str(len(error_list)-1)


def display_errors(error_list):
    'Loop and print from the array'

    for idx,err in enumerate(error_list):
        print 'ERR%-5d %s' % (idx, err)


def canonicalise_mac(mac_str):
    'Standardise on the MAC address format'

    # the 'mac_unix_expanded' format is only in a later version of the netaddr module
    # create a custom format
    class mac_custom(mac_unix): pass
    mac_custom.word_fmt = '%.2x'

    try:
        mac = EUI(mac_str, dialect=mac_custom)
        #mac.dialect = mac_unix_expanded
        #mac.dialect = mac_unix
    except core.AddrFormatError:
        print "ERROR: unable to parse '%s' as a MAC address; skipping" % mac_str
        return ''

    # return a string
    return '%s' % mac


if __name__ == '__main__':
    main()

