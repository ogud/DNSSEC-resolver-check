# #######################################################################
# Copyright (c) 2013, Bob Novas, Shinkuro, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  - Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  - Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# #######################################################################

"""
This is a port of Squery.java (ogud@shinkuro.com) to Python
This code requires dnspython (dnspython.org)

$Id: Squery.py 447 2013-08-22 18:05:56Z bob.novas $
"""

import dns
import dns.resolver
import dns.version
from dns.resolver import Answer, NoMetaqueries, NoNameservers, NoAnswer, NXDOMAIN
import sys
import socket
import time

class Resolver(dns.resolver.Resolver):
    """
    override dnspython query - the stock implementation of query does not return
    an answer on SERVFAIL, it either times out retrying if retry_servfail is True, 
    or removes the nameserver from the resolver (brilliant!) if retry_servfail is False.
    
    This implementation just returns the answer on SERVFAIL, which is what we need.
    Same for REFUSED - return an answer.
    
    TBD: need to fix the truncation code- this implementation ALWAYS retries truncated w/TCP.
    """
    
    def __init__(self, filename='/etc/resolv.conf', configure=True):
        super(Resolver, self).__init__(filename='/etc/resolv.conf', configure=True)
        
    def reset(self):
        """
        Reset the subclass behavior variables.
        
        These variables change the behavior of the superclass query method. The
        default is the old behavior. Setting a variable to True enables the new
        behavior.
        
        return_servfail - return an Answer when the resolver returns SERVFAIL
        return_refused  - ditto, for REFUSED
        no_tcp_on_tc    - don't fallback to TCP if UDP gets TC (truncate) bit
        """
        super(Resolver, self).reset()
        
        self.return_servfail = False
        self.return_refused = False
        self.no_tcp_on_tc = False
        
        
    def query(self, qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
              tcp=False, source=None, raise_on_no_answer=True, source_port=0):
        """Query nameservers to find the answer to the question.

        The I{qname}, I{rdtype}, and I{rdclass} parameters may be objects
        of the appropriate type, or strings that can be converted into objects
        of the appropriate type.  E.g. For I{rdtype} the integer 2 and the
        the string 'NS' both mean to query for records with DNS rdata type NS.

        @param qname: the query name
        @type qname: dns.name.Name object or string
        @param rdtype: the query type
        @type rdtype: int or string
        @param rdclass: the query class
        @type rdclass: int or string
        @param tcp: use TCP to make the query (default is False).
        @type tcp: bool
        @param source: bind to this IP address (defaults to machine default IP).
        @type source: IP address in dotted quad notation
        @param raise_on_no_answer: raise NoAnswer if there's no answer
        (defaults is True).
        @type raise_on_no_answer: bool
        @param source_port: The port from which to send the message.
        The default is 0.
        @type source_port: int
        @rtype: dns.resolver.Answer instance
        @raises Timeout: no answers could be found in the specified lifetime
        @raises NXDOMAIN: the query name does not exist
        @raises YXDOMAIN: the query name is too long after DNAME substitution
        @raises NoAnswer: the response did not contain an answer and
        raise_on_no_answer is True.
        @raises NoNameservers: no non-broken nameservers are available to
        answer the question."""

        if isinstance(qname, (str, unicode)):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, (str, unicode)):
            rdtype = dns.rdatatype.from_text(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            raise NoMetaqueries
        if isinstance(rdclass, (str, unicode)):
            rdclass = dns.rdataclass.from_text(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            raise NoMetaqueries
        qnames_to_try = []
        if qname.is_absolute():
            qnames_to_try.append(qname)
        else:
            if len(qname) > 1:
                qnames_to_try.append(qname.concatenate(dns.name.root))
            if self.search:
                for suffix in self.search:
                    qnames_to_try.append(qname.concatenate(suffix))
            else:
                qnames_to_try.append(qname.concatenate(self.domain))
        all_nxdomain = True
        start = time.time()
        for qname in qnames_to_try:
            if self.cache:
                answer = self.cache.get((qname, rdtype, rdclass))
                if not answer is None:
                    if answer.rrset is None and raise_on_no_answer:
                        raise NoAnswer
                    else:
                        return answer
            request = dns.message.make_query(qname, rdtype, rdclass)
            if not self.keyname is None:
                request.use_tsig(self.keyring, self.keyname,
                                 algorithm=self.keyalgorithm)
            request.use_edns(self.edns, self.ednsflags, self.payload)
            if self.flags is not None:
                request.flags = self.flags
            response = None
            #
            # make a copy of the servers list so we can alter it later.
            #
            nameservers = self.nameservers[:]
            backoff = 0.10
            while response is None:
                if len(nameservers) == 0:
                    raise NoNameservers
                for nameserver in nameservers[:]:
                    timeout = self._compute_timeout(start)
                    try:
                        if tcp:
                            response = dns.query.tcp(request, nameserver,
                                                     timeout, self.port,
                                                     source=source,
                                                     source_port=source_port)
                        else:
                            response = dns.query.udp(request, nameserver,
                                                     timeout, self.port,
                                                     source=source,
                                                     source_port=source_port)
                            if response.flags & dns.flags.TC and not self.no_tcp_on_tc:
                                # Response truncated; retry with TCP.
                                timeout = self._compute_timeout(start)
                                response = dns.query.tcp(request, nameserver,
                                                       timeout, self.port,
                                                       source=source,
                                                       source_port=source_port)
                    except (socket.error, dns.exception.Timeout):
                        #
                        # Communication failure or timeout.  Go to the
                        # next server
                        #
                        response = None
                        continue
                    except dns.query.UnexpectedSource:
                        #
                        # Who knows?  Keep going.
                        #
                        response = None
                        continue
                    except dns.exception.FormError:
                        #
                        # We don't understand what this server is
                        # saying.  Take it out of the mix and
                        # continue.
                        #
                        nameservers.remove(nameserver)
                        response = None
                        continue
                    except EOFError:
                        #
                        # We're using TCP and they hung up on us.
                        # Probably they don't support TCP (though
                        # they're supposed to!).  Take it out of the
                        # mix and continue.
                        #
                        nameservers.remove(nameserver)
                        response = None
                        continue
                    rcode = response.rcode()
                    if rcode == dns.rcode.YXDOMAIN:
                        raise YXDOMAIN
                    if rcode == dns.rcode.NOERROR or \
                           rcode == dns.rcode.NXDOMAIN or \
                           (rcode == dns.rcode.SERVFAIL and self.return_servfail) or \
                           (rcode == dns.rcode.REFUSED and self.return_refused):
                        break
                    #
                    # We got a response, but we're not happy with the
                    # rcode in it.  Remove the server from the mix if
                    # the rcode isn't SERVFAIL.
                    #
                    if rcode != dns.rcode.SERVFAIL or not self.retry_servfail:
                        nameservers.remove(nameserver)
                    response = None
                if not response is None:
                    break
                #
                # All nameservers failed!
                #
                if len(nameservers) > 0:
                    #
                    # But we still have servers to try.  Sleep a bit
                    # so we don't pound them!
                    #
                    timeout = self._compute_timeout(start)
                    sleep_time = min(timeout, backoff)
                    backoff *= 2
                    time.sleep(sleep_time)
            if response.rcode() == dns.rcode.NXDOMAIN:
                continue
            all_nxdomain = False
            break
        if all_nxdomain:
            raise NXDOMAIN
        answer = Answer(qname, rdtype, rdclass, response,
                        raise_on_no_answer)
        if self.cache:
            self.cache.put((qname, rdtype, rdclass), answer)
        return answer
    

class Squery(object):
    """
    """
    TTL = -1

    def __init__(self):
        
        dnspython_version = dns.version.version
        if dnspython_version < '1.11.0':
            raise ValueError("You have dnspython %s. You need dnspython 1.11.0 or better" 
                             % (dnspython_version, ))
        
        self.saw_timeout = False
        self.set_zone("submit.dnssecready.net.")
        self.ignore_truncation = True
        self.ttl = 0

    @classmethod
    def println(cls, o):
        """
        Print a debug message

        @param o: message to print
        @type o: L{string}
        """
        print o

    def set_ttl(self, val):
        """
        Set the Time to Live value of a query

        @param val: time to live value
        @type val: L{float}
        """
        self.ttl = val

    def get_ttl(self):
        """
        Get the Time to Live value of a query

        @rtype: L{float}
        @return: Time to live value
        """
        return self.ttl

    def set_ignoreTruncation(self, val):
        self.ignore_truncation = val

    def get_ignoreTruncation(self):
        return self.ignore_truncation

    def query_timeout(self):
        """
        Query whether a timeout occurred.

        @rtype: L{boolean}
        @return: Timeout exception occurred in a query on this object
        """
        return self.saw_timeout

    def set_zone(self, zone_name):
        """
        Set the zone name and the getting_address

        @param zone_name: the zone name
        @type zone_name: L{string}
        """

        self.zone_name = zone_name
        self.getting_address = "whatsmyip." + self.zone_name

    def get_zone(self):
        """
        Get the zone_name

        @rtype: L{string}
        @return: The zone name
        """
        return self.zone_name

    @classmethod
    def Str_to_Name(cls, name):
        """
        Translate a string to a dns.Name object

        @param name: the name to translate
        @type name: L{string}
        """
        my_name = None
        try:
            my_name = dns.name.from_text(name, dns.name.root)
        except:
            cls.println("Name error rrsig_check: %s" % (name, ))
        return my_name

    @classmethod
    def get_resolver(cls, resolver, debug=False, tcp=False):
        """
        @param resolver: The resolver to query, as a dotted IPv4 address
        @type resolver: L{string}

        @param debug: if True, print some debug output
        @type debug: L{boolean}

        @rtype: L{dns.resolver.Resolver}
        @return: an instance of a resolver object
        """
        try:
            rslvr = Resolver()
            rslvr.nameservers = [resolver]
            
            # Tack a instance variable onto the Resolver instance
            # that says whether to use TCP or not.  If use_tcp is
            # True, then the queries will be over TCP only.
            rslvr.use_tcp = tcp

            # Set the alternate behavior flags to return an Answer 
            # on SERVFAIL and REFUSED. 
            rslvr.return_servfail = True
            rslvr.return_refused = True

            # change the timeout (lifetime) to 10 seconds from the default 30.
            rslvr.lifetime = 10.0

            # for debugging the resolver query code, make the lifetime huge
            #rslvr.lifetime = 1000000.0 
            
            if debug:
                cls.println("Resolver=%s" % (rslvr, ))
            return rslvr

        except:
            return None


    def make_query(self, domain, rdatatype, resolver, debug=False, noRec=False):
        """
        @param domain: domain name to issue query against
        @type domain: L{string}

        @param rdatatype: type of RRSet queried for
        @type rdatatype: L{dns.rdatatype}

        @param resolver: resolver to ask to answer the query
        @type resolver: L{dns.resolver.Resolver}

        @param debug: if True, print some debug output
        @type debug: L{boolean}

        @param noRec: No Recursion (set the RD flag in the query)
        @type noRec: L{Boolean}
        """
        name = self.Str_to_Name(domain)
        if not name:
            return name
        
        if noRec:
            flags = resolver.flags
            flags &= ~dns.flags.RD
            resolver.set_flags(dns.flags.RD)

        ans = None
        try:
            ans = resolver.query(name, rdatatype, rdclass=dns.rdataclass.IN, tcp=resolver.use_tcp, raise_on_no_answer=False)
            if debug: self.println("%s %s: %s" % (domain, dns.rdatatype.to_text(rdatatype), ans.response.to_text(), ))
        except dns.exception.Timeout:
            self.saw_timeout = True
            if debug: self.println("Exception: timeout")
        except dns.resolver.NoAnswer:
            if debug: self.println("Exception: %s" % (sys.exc_info()[0], ))
        except:
            if debug: self.println("Exception: %s" % (sys.exc_info()[0], ))

        return ans

    def addr_lookup(self, resolver, name, debug=False):
        """
        Lookup the address of name using a given resolver

        @param resolver: resolver to ask to answer the query
        @type resolver: L{string}

        @param name: the name of the resolver to lookup
        @type name: L{string}

        @param debug: if True, print some debug output
        @type debug: L{boolean}
        """
        if not isinstance(resolver, basestring):
            raise ValueError("resolver should be a dotted ip address string")
                             
        reslvr = self.get_resolver(resolver, debug=debug)
        if not reslvr: return reslvr

        ans = self.make_query(name, dns.rdatatype.A, reslvr, debug)
        if ans and ans.response and ans.response.answer:
            rdataset = ans.response.answer[0].to_rdataset()
            if rdataset:
                #print "type(rdataset)=%s" % (type(rdataset), )
                #print "type(rdataset[0])=%s" % (type(rdataset[0]), )
                return rdataset[0].to_text()

        return None

    def Forged_Address(self, resolver, debug=False):
        """
        Determine if a resolver is returning a forged address ty testing
        against the "well known" address of fixedaddress.dnssecready.net

        @param resolver: the IPv4 dotted address of the resolver to use
        @type resolver: L{string}

        @param debug: if True, print some debug output
        @type debug: L{boolean}
        """
        tst = self.addr_lookup(resolver, "fixedaddress.dnssecready.net.", debug)
        return not (tst == "127.252.253.254")