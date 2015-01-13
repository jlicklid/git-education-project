#! /usr/bin/env python

"""
Copyright (c) 2003-2005 Jose Nazario <jose@monkey.org>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   This product includes software developed by Jose Nazario.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

__author__ = 'Jose Nazario <jose@monkey.org>'
__copyright__ = 'Copyright (c) 2005 Jose Nazario'
__license__ = 'BSD 3-clause'
__url__ = 'http://monkey.org/~jose/software/flowgrep/'
__version__ = '0.9.0'

# REQUIREMENTS:
# libnids (and libnet, libpcap)
# python 2.2 or later
# pynids: http://pilcrow.madison.wi.us/pynids/

# some of main() shamelessly stolen from the pynids Example code ...

# standard imports
import getopt, os, pwd, re, string, struct, sys, time

# local imports ...
import nids

# stuff for libdistance
try: 
    import distance
    havedist = 1
except ImportError: havedist = 0

# global lists ...
crelist = []		# list of client REs (compiled)
srelist = []		# list of server REs (compiled)
strlist = []		# client/server strings for distance calculations
logdir = "."		# path to log directory
caught = []		# list of caught tuples (((src, sport), (dst, dport)))
distalg = ''		# libdistance algorithm to use
dist = 0		# default to exact match for libdistance

# dict of cmdline flags, defaults
flags = {'c': 0, 'k': 0, 'l': 0, 's':0, 'v': 0, 'x': 0}

def long2ip(val):
    # convert long IP addresses to dotted quad notation
    slist = []
    for x in range(0,4):
        slist.append(str(int(val >> (24 - (x * 8)) & 0xFF))) 
    return ".".join(slist)

def fuzzy_match(needle, haystack):
    matchlen = len(needle)
    # matchlen = len(needle) + int(dist) - 2
    match = 0
    for i in xrange(0, len(str(haystack)) - matchlen):
        try: 
            print '%s vs %s' % \
                (distalg(str(haystack[i:i + matchlen]), needle), dist)
            if distalg(str(haystack[i:i + matchlen]), needle) <= float(dist): 
                match = 1
        except: pass
    return match

def usage(comment):
    print comment
    sys.exit(-1)

def logPkt(addr, payload, proto=17):
    # log a single packet, for UDP and other IP (non-TCP)
    ip_p = {1:'icmp', 2:'igmp', 6:'tcp', 17:'udp', 41:'ipv6', 47:'gre', 
            50:'esp', 51:'ah', 58:'icmp6', 94:'ipip', 115:'l2tp', 255:'raw'}
    if proto == 17:
        fname = "%s/%s-%s-%s-%s-%s-udp" % (logdir, int(time.time()), 
		 addr[0][0], addr[0][1], addr[1][0], addr[1][1])
    else:
        proto = ip_p.get(proto, proto)
        fname = "%s/%s-%s-%s-%s" % (logdir, int(time.time()), 
		 long2ip(addr[0]), long2ip(addr[1]), proto)
    f = open(fname, "w")
    f.write(payload)
    f.close()
    if flags['x']:
        print fname

def logTcp(tcp):
    # client to server
    fname = "%s/%s-%s-%s-%s-%s-tcp" % (logdir, int(time.time()), 
	     tcp.addr[0][0], tcp.addr[0][1], tcp.addr[1][0], tcp.addr[1][1])
    try: f = open(fname, "w")
    except: 
        print "unable to log to", logdir
        return
    f.write(tcp.server.data)
    f.close()
    if flags['x'] and fname: print fname
    # server to client
    fname = "%s/%s-%s-%s-%s-%s-tcp" % (logdir, int(time.time()), 
 	     tcp.addr[1][0], tcp.addr[1][1], tcp.addr[0][0], tcp.addr[0][1])
    f = open(fname, "w")
    f.write(tcp.client.data)
    f.close()
    if flags['x'] and fname: print fname

def handleTcp(tcp):
    # format of tcp.addr: ((src, sport), (dst, dport))

    global caught
    end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
    if tcp.nids_state == nids.NIDS_JUST_EST:
        tcp.client.collect = 1
        tcp.server.collect = 1

    elif tcp.nids_state == nids.NIDS_DATA:
        match = 0
        # keep all of the stream's new data
        tcp.discard(0)
        # we do the checks now, taking the performance hit, so we can
        # kill ASAP when we match ...
        for serverre in srelist:
            try:  
                if flags['s'] and serverre.search(tcp.client.data): match = 1
            except: pass
        for clientre in crelist:
            try: 
                if flags['c'] and clientre.search(tcp.server.data): match = 1
            except: pass
        for s in strlist:
            if fuzzy_match(tcp.client.data, s): match = 1
            if fuzzy_match(tcp.server.data, s): match = 1
        if match:
            if tcp.addr not in caught: caught.append(tcp.addr)
            if flags['k'] and not flags['v']: tcp.kill()
        elif not match and flags['v']:
            if tcp.addr not in caught: caught.append(tcp.addr)
            if flags['k']: tcp.kill()
     
    elif tcp.nids_state in end_states and flags['l']:
        if tcp.addr in caught and not flags['v']: logTcp(tcp)
        elif tcp.addr not in caught and flags['v']: logTcp(tcp)

def handleUdp(addr, payload, pkt):
    # format of addr: ((src, sport), (dst, dport))
    match = 0
    for clientre in crelist:
        if clientre.search(payload): match = 1
    for serverre in srelist:
        if serverre.search(payload): match = 1
    for s in strlist:
        if fuzzy_match(s, payload): match = 1
    if flags['l']:
        if match and not flags['v']: logPkt(addr, payload)
        if not match and flags['v']: logPkt(addr, payload)

def handleIp(pkt):
    # handle an IP packet here ... dpkt, perhaps?
    v_hl, tos, len, id, off, ttl, p, sum, src, dst = \
	struct.unpack("!BBHHHBBHII", pkt[0:20])
    if p & 0xff == 6 or p & 0xff == 17:
        return					# ignore
    try: 
        if len(pkt) < 20: return
    except: pass
    proto = "proto%d" % (int(p) & 0xff)
    addr = (src, dst)

    # do the search 
    match = 0
    payload = pkt[20:]				# XXX, ignores v_hl
    for clientre in crelist:
        if clientre.search(payload): match = 1
    for serverre in srelist:
        if serverre.search(payload): match = 1
    for s in strlist:
        if fuzzy_match(s, payload): match = 1
    if flags['l']:
        if match and not flags['v']: logPkt(addr, payload, proto)
        if not match and flags['v']: logPkt(addr, payload, proto)

def main():
    global flags, crelist, srelist, logdir, distalg, dist
    compflags = re.MULTILINE 	# add ignore case? (add re.IGNORECASE)	-i
    NOTROOT = "nobody"   	# non-root user to run as		-u
    servers = []		# list of cmdline REs for server
    clients = []		# list of cmdline REs for client

    usagestr = """%s: TCP stream/UDP/IP payload 'grep' utility
    Usage: %s OPTIONS [FILTER]

    where OPTIONS are any of the following:
       -a [pattern] 	match any stream with pattern
       -c [pattern] 	match client stream with pattern
       -D [num]		distance score for libdistance-based match
       -d [device]	input device 
       -E [name]	string distance algorithm to use
                        (one of: levenshtein, damerau, hamming, jaccard)
       -e [string]	string to compare against for distance-based matches
       -F [file]	obtain server patterns from file, one per line
       -f [file]	obtain client patterns from file, one per line
       -i 		case insensitive match
       -k 		kill matched stream (TCP only)
       -l [dir]		log matched flows relative to dir (default: .)
       -r [file]	input file (in pcap(3) format)
       -s [pattern]	match server stream with pattern
       -u [username]	run as username (default: nobody)
       -V		print version information and exit
       -v 		select non-matching input
       -x 		print logged filenames (for use with xargs(1))

    [FILTER]		pcap(3) filter expression
 
      UDP and IP payloads will test any pattern (no stream to test).""" % (sys.argv[0], sys.argv[0])

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'a:c:D:d:E:e:F:f:ikl:r:s:u:Vvxh')
    except:
        usage(usagestr)

    for o, a in opts:
        if o == '-a':
            flags['c'] = 1
            flags['s'] = 1
            clients.append(a)
            servers.append(a)
        elif o == '-c':
            flags['c'] = 1
            clients.append(a)
        elif o == '-d':
            nids.param("device", a)
        elif o == '-D':
            if havedist: dist = a
            else: 
                print 'Distance-based match requested, don\'t have libdistance'
                sys.exit(1)
        elif o == '-e':
            if havedist == 0:
                print 'Distance-based match requested, don\'t have libdistance'
                sys.exit(1)
            strlist.append(a)            
        elif o == '-E':
            if havedist == 0:
                print 'Distance-based match requested, don\'t have libdistance'
                sys.exit(1)
            if a.lower().find('le') == 0: distalg = distance.levenshtein
            elif a.lower().find('da') == 0: distalg = distance.damerau
            elif a.lower().find('ja') == 0: distalg = distance.jaccard
            elif a.lower().find('ha') == 0: distalg = distance.hamming
            else:
                print 'Unsupported algorithm for libdistance'
                sys.exit(1)
        elif o == '-F':
            try: 
                f = open(a, "r")
            except:
                print "unable to open file", a
                sys.exit(1)
            servers.extend(map(lambda x: x.replace('\n', ''), f.readlines()))
            flags['s'] = 1
            f.close()
        elif o == '-f':
            try: f = open(a, "r")
            except:
                print "unable to open file", a
                sys.exit(1)
            clients.extend(map(lambda x: x.replace('\n', ''), f.readlines()))
            flags['c'] = 1
            f.close()
        elif o == "-i":
            compflags |= re.IGNORECASE
        elif o == "-k":
            flags['k'] = 1
        elif o == "-l":
            logdir = a
            flags['l'] = 1
        elif o == "-r": 
            nids.param("filename", a)
        elif o == "-s": 
            flags['s'] = 1
            servers.append(a)
        elif o == "-u":
            NOTROOT = a
        elif o == "-V":
            print "flowgrep version", __version__
            sys.exit(0)
        elif o == "-v":
            flags['v'] = 1
        elif o == "-x":
            flags['x'] = 1
        elif o == "-h":
            usage(usagestr)

    # delay compilation until now in case REs specified before -i
    crelist = map(lambda x: re.compile(x, compflags), clients)
    srelist = map(lambda x: re.compile(x, compflags), servers)

    print 'args: ', args
    if len(args) > 0:
        nids.param("pcap_filter", ' '.join(args))

    nids.param("scan_num_hosts", 0)  # disable portscan detection
    try: nids.init()
    except nids.error, e:
        print "initialization error", e
        sys.exit(1)

    # os.system('sysctl -w net.link.ether.inet.apple_hwcksum_rx = 0')
    # os.system('sysctl -w net.link.ether.inet.apple_hwcksum_tx = 0')

    (uid, gid) = pwd.getpwnam(NOTROOT)[2:4]
    os.setgroups([gid,])
    os.setgid(gid)
    os.setuid(uid)
    if 0 in [os.getuid(), os.getgid()] + list(os.getgroups()):
        print "error - drop root, please!"
        sys.exit(1)

    nids.register_tcp(handleTcp)
    nids.register_udp(handleUdp)
    nids.register_ip(handleIp)

    while 1: 
        try: nids.run()			# loop forever 
        except KeyboardInterrupt: break
    sys.exit(1)

if __name__ == '__main__':
    main()
