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
This is a port of DRC_resolver_check.java (ogud@shinkuro.com) to Python

$Id: DNSSEC_resolver_check.py 444 2013-08-16 15:51:31Z bob.novas $
"""

import dns
import dns.version
import sys
from Squery      import Squery
from rrSetSource import RRSetSource

class DNSSEC_resolver_check(Squery):
    """
    """
    revision = "$Revision: 444 $"

    def init_variables(self):
        super(DNSSEC_resolver_check, self).__init__()

        self.abort = False
        self.debug = False
        self.submit_report = True
        self.show_report = False
        self.detailed_report = False
        self.reports_failed = 0
        self.tests_run = 0
        self.abort_test = 0
        self.reason = ""
        self.ad_current = False
        self.ed_buff = 2048
        self.ad_seen = False
        self.big_ok = False
        self.saw_timeout = False
        self.response_size = 0
        self.rcode = 0
        self.tcp_works = False
        self.waran_msg = ""
        self.failed_test = False
        self.test = [False]*14
        self.test_performed = [False]*14
        self.ad_res = [False]*14
        self.timeout = [False]*14
        self.timeout_is_failure = [True]*7 + [False]*7
        self.test_msg = [""]*14
        self.test_size = [0]*14
        self.R_code = [0]*14
        self.is_tc_set = False
        self.user_message = ".Msg="

        self.test_name = ["None", "Recursive Resolver", "EDNS0 Support", "RFC3597/Unknown Support",
                          "TCP Support", "DNAME Support", "Large UDP", "DO support + RRSIG in answer",
                          "DS found", "Signed DNAME", "NSEC Seen", "NSEC3 Seen", "Big Signed", "Returns Bogus"]
        assert len(self.test_name) == 14

        self.zone = "submit.dnssecready.net."
        self.submit = "report.shinkuro.com."
        self.set_zone(self.zone)
        self.init_done = True

    def __init__(self):
        self.init_done = False
        self.init_variables()

    def set_reason(self, msg):
        self.reason = msg

    def add_reason(self, msg):
        self.reason += msg

    def get_reason(self):
        return self.reason

    @classmethod
    def get_version(cls):
        return cls.revision.split()[1]

    @classmethod
    def get_local_resolvers(cls):
        return dns.resolver.Resolver().nameservers

    def set_abort(self, val):
        self.abort = val

    def set_message(self, val):
        if val:
            self.user_message = ".Msg=%s" % val

    def set_show_test_results(self, val):
        self.show_report = val

    def set_submit_report(self, val):
        self.submit_report = val

    def set_debug(self, val):
        self.debug = val

    def set_verbose_report(self, val):
        self.detailed_report = val

    def ad_reset(self):
        self.ad_seen = False
        self.ad_current = False

    def ad_add(self, val):
        self.ad_current = not not val
        self.ad_seen = self.ad_seen or val

    def clear_tc_bit(self):
        self.is_tc_set = False

    def set_tc_bit(self, val):
        self.is_tc_set = val

    def get_tc_bit(self):
        return self.is_tc_set

    def report_reset(self):
        if not self.init_done:
            self.init_variables()
        else:
            for i in range(len(self.test)):
                self.test_performed[i] = self.test[i] = self.ad_res[i] = self.timeout[i] = False
                self.test_msg[i] = None
                self.test_size[i] = 0
                self.R_code[i] = 0
        self.tests_run = 0
        self.abort_test = 0
        self.failed_test = False
        self.is_tc_set = False
        self.saw_timeout = False
        self.user_message = ".Msg="

    def push_abort(self, val):
        save_abort = self.abort
        self.abort = val
        return save_abort

    def pop_abort(self, val):
        self.push_abort(val)

    def make_query(self, domain, rdatatype, resolver, debug=False, noRec=False):
        answer = super(DNSSEC_resolver_check, self).make_query(domain, rdatatype, resolver, debug, noRec)
        if answer is not None:
            self.response_size = len(answer.response.to_wire())
        return answer

    def response_ok(self, res, domain, rdtype):
        ans_container = self.make_query(domain, rdtype, res, self.debug);
        if ans_container is None or ans_container.response is None:
            return None

        response = ans_container.response
        if self.debug:
            print(response)

        ad = response.flags & dns.flags.AD
        self.ad_add(ad); # log ad bit

        if response.rcode() != dns.rcode.NOERROR:
            self.add_reason( "RCODE=%s" % (response.rcode(), ))
            return None

        return response;

    def register_test_result(self, test_number, result, msg, bad):

        if self.debug:
            self.println("Registering %d %s %s" % (test_number, result, bad, ))

        self.test_performed[test_number] = True
        self.timeout[test_number] = self.query_timeout()
        self.tests_run += 1
        self.ad_res[test_number] = self.ad_current
        self.ad_current = False
        self.test_size[test_number] = self.response_size
        self.test_msg[test_number] = "%s -- %s" % (msg, self.get_reason(), )
        self.R_code[test_number] = self.rcode

        if (self.debug):
            self.println(" in register result %s %d %d" % (bad, self.rcode, self.response_size, ))

        if result == bad:
            # got bad result
            if self.debug:
                self.println(" in register bad %s %s %s" % (bad, self.rcode, self.response_size, ))
            self.failed_test = True
            if self.timeout[test_number] and self.timeout_is_failure[test_number]:
                if self.rcode > 0:
                    if self.debug:
                        self.println(" in register rcode %s %s %s" % (bad, self.rcode, self.response_size, ))
                    self.abort_test = self.tests_run
                    return True
                self.set_reason("")
                return self.abort
            return self.abort

        else:
            #got expected result...
            self.test[test_number] = True
            return False

    def display_result(self):
        self.println(self.get_reason())

    def test_letter(self, i):
        letter = "Y"
        if self.test_performed[i] == False:
            letter = "S"
        elif self.R_code[i] > 0:
            letter = "R=%s," % dns.rcode.to_text(self.R_code[i])
        elif self.timeout[i] == True and self.timeout_is_failure[i] == False:
            letter = "T"
        elif self.test[i] == True:
            letter = "A" if self.ad_res[i] else "P"
        else:
            letter = "F" if not self.ad_res[i] else "X"
        return letter;

    def test_results(self):
        out = ""             # Summary line
        if self.failed_test:
            # First report on each test
            rep = ""         # Explanation of failed tests
            for i in range(len(self.test)):
                out += " T%d%s/%d" % (i, self.test_letter(i), self.test_size[i], )
                if self.test_performed[i] == False:
                    rep += " T%d %s := Skipped\n" % (i, self.test_name[i], )
                elif self.test[i] == False: # failed
                    if self.test_msg[i]:
                        rep += " T%d %s := %s\n" % (i, self.test_name[i], self.test_msg[i], )
            if self.detailed_report:
                out += "\nFailed tests:\n" + rep
        elif self.tests_run > 1:
            out = "All tests passed"
        else:
            out = "No Tests Run"
        return out

    def string_result(self):
        out = ''
        top = len(self.test) if self.abort_test == 0 else self.abort_test
        for i in range(1, top):
            out += self.test_letter(i)
        return out

    def count_rr(self, section, name, rdtype):
        source = RRSetSource(section)
        return source.count(rdtype)

    def first_check(self, res, domain, qtype, edns, log_ad=False):
        answer = self.make_query(domain, qtype, res, self.debug)
        if answer is None or answer.response is None:
            return False

        response = answer.response

        ad = log_ad and (response.flags & dns.flags.AD)
        self.ad_add(ad)  # log AD bit

        if self.debug:
            self.println(response)

        self.rcode = response.rcode()
        if self.rcode != dns.rcode.NOERROR:
            self.add_reason("DNS Error %s" % (dns.rcode.to_text(self.rcode), ))
            return False

        if not response.flags & dns.flags.RA:
            self.add_reason("Error: Not a recursive resolver - RA flag missing")
            return False

        Ans = response.answer

        name = self.Str_to_Name(domain);
        if self.count_rr(Ans, name, qtype) == 0:
            self.add_reason( "No %s seen in answer" % (dns.rdatatype.to_text(qtype), ))
            return False

        if edns:
            if not response.ednsflags:
                self.add_reason("No Opt returned")
                return False
            
            size = len(response.to_wire())
            if(size > 512):
                self.big_ok = True

            payloadSize = response.payload
            if payloadSize < size:
                self.add_reason("Small ENDS reported %d < %d" % (payloadSize, size, ))

        return True

    def tcp_test(self, resolver):

        self.tcp_works = False;
        tcp = self.get_resolver(resolver, tcp=True, debug=self.debug)
        if not tcp:
            return False

        if not self.first_check(tcp, "net.", dns.rdatatype.SOA, False):
            self.add_reason( "TCP not offered")
            return False

        self.tcp_works = True
        return True

    def dname_check(self, res, domain, rdtype, target, count_rrsig):
        ans_container = self.make_query(domain, rdtype, res, self.debug)
        if not ans_container or not ans_container.response or not ans_container.response.answer:
            self.add_reason( "DNAME lookup failed")
            return False

        answer = ans_container.response.answer
        if self.debug:
            self.println(answer)

        # log ad bit
        ad = count_rrsig and (ans_container.response.flags & dns.flags.AD)
        self.ad_add(ad)

        cnt = len(answer)
        if cnt <= 0:
            self.add_reason( "Empty DNAME Answer")
            return False

        name = self.Str_to_Name(domain)
        if self.count_rr(answer, name, dns.rdatatype.DNAME) == 0:
            self.add_reason("NO DNAME seen in answer")
            return False

        if count_rrsig:
            source = RRSetSource(answer)
            if cnt < 2:
                #DNAME and target RRset are signed
                self.add_reason("Not enoght records in DNAME answer")
                return False

            rrset = source.get_rrset(dns.rdatatype.DNAME)
            if not source.find_covering_rrsigset(rrset):
                self.add_reason("Missing RRSIG(DNAME)")
                return False

            last_rrset = answer[len(answer)-1]
            res_target = last_rrset.name.to_text()
            if res_target != target:
                self.addr_reason("DNAME name mismatch %s !+ %s" % (target, res_target, ))
                return False

        return True

    def positive_check(self, res, domain, rdtype, ad):
        self.clear_tc_bit()
        response = self.response_ok(res, domain, rdtype)
        if not response:
            self.add_reason("empty response")
            return False

        tc = response.flags & dns.flags.TC
        self.set_tc_bit(tc)


    def negative_check(self, res, domain, rdtype, ad):
        my_name = self.Str_to_Name(domain)
        if not my_name:
            return False

        response = self.response_ok(res, domain, rdtype)
        if not response:
            return False

        if len(response.answer):
            self.add_reason( "Answer != empty %s %s" % (domain, dns.rdatatype.to_text(rdtype), ))
            return False

        auth = response.authority
        if len(auth) == 0:  # empty authority
            self.add_reason("Empty negative answer")
            return False
        elif self.count_rr(auth, my_name, dns.rdatatype.SOA) > 0:
            # must be backwards compatibility
            # Now count the records that I expect to find in the authority seciton
            n  = self.count_rr(auth, my_name, dns.rdatatype.NSEC)  #either NSEC or NSEC3
            n3 = self.count_rr(auth, my_name, dns.rdatatype.NSEC3) # must be there
            if (n + n3) > 0 and (n == 0 or n3 == 0):
                # make sure there are NSEC or NSEC3 but not both
                x = self.count_rr(auth, my_name, dns.rdatatype.RRSIG) # signatures present ?
                if x > 1:  # at least SOA and one NSECx record must be signed
                    return True
                else:
                    self.add_reason("Not enough RRSIG (%d)" % (x, ))
            else:
                self.add_reason("Missing NSEC/NSEC3 %d/%d" % (n, n3, ))
        return False

    def expect_failure(self, res, domain, rdtype):
        rrr = self.get_reason()
        response = self.response_ok(res, domain, rdtype);
        if not response:
            self.set_reason(rrr)
            return True
        else:
            my_name = self.Str_to_Name(domain)
            ans = response.answer
            so = self.count_rr(ans, my_name, rdtype)
            rsig = self.count_rr(ans, my_name, dns.rdatatype.RRSIG)
            rdtype_as_string = dns.rdatatype.to_text(rdtype)
            self.println("expect_failure %s %s Got:%s != SERVFAIL # %s %s #RRSI %d"
                         % (domain, rdtype_as_string, response.rcode(), rdtype_as_string, so, rsig, ))
            if self.debug:
                self.println(response) # not the whole packet need to parse it

        return False

    def run_tests(self, resolver, fail_allowed):
        self.big_ok = False
        msg = None

        res = self.get_resolver(resolver, debug=self.debug)
        if not res:
            self.add_reason("Cannot create resolver")
            return False

        #does it answer questions?
        msg = "Can't resolve com. soa not a useful resolver "
        first_one = self.first_check(res, "com.", dns.rdatatype.SOA, False)
        if self.register_test_result(1, first_one, msg, False):
            return False
        if not first_one:
            return False
        
        # do not fall back to TCP
        res.no_tcp_on_tc = True

        #check for old DNS extensions
        res.use_edns(0, dns.flags.DO, self.ed_buff)
        
        x = self.push_abort(True)
        msg = "org DNSKEY lookup failed RFC4034"
        if self.register_test_result(2, self.first_check(res, "org.", dns.rdatatype.DNSKEY, True), msg, False):
            fail_allowed -= 1
            if fail_allowed < 0:
                return False
        self.pop_abort(x)

        #check for new/unknown records (update over time)
        msg = "Unknown RR failure RFC3597"
        fc = self.first_check(res, "tlsa.ogud.com", dns.rdatatype.TLSA, True)
        if self.register_test_result(3, fc, msg, False) or not fc:
            fail_allowed -= 1
            if fail_allowed < 0:
                return False

        #is TCP supported?
        msg = "TCP Failed RFC1035/RFC5966 violation"
        if (self.register_test_result(4, self.tcp_test(resolver), msg, False)):
            return True

        #is DNAME supported and returned?
        msg = "DNAME Not Supported RFC2672/RFC6672"
        if self.register_test_result(5,
                                     self.dname_check(res, "grade.goal.ogud.com", dns.rdatatype.TXT, "grade.shinkuro.com.", False),
                                     msg,
                                     False):
            return True

        # Make sure we got some answer that was bigger than 512 bytes i.e. via
        # Edns0 or TCP
        msg = "No answers > 512 seen"
        if self.register_test_result(6, self.big_ok, msg, False):
            return True

        return self.dnssec_tests(res)

    def dnssec_tests(self, res):
        res.use_edns(0, dns.flags.DO, self.ed_buff)
        self.ad_reset()

        msg = "No Signed SOA RFC4035"
        if self.register_test_result(7,
                                     self.positive_check(res, "iab.org.", dns.rdatatype.SOA, True),
                                     msg,
                                     False):
            return False

        msg = "no DS received RFC4035"
        if self.register_test_result(8,
                                     self.positive_check(res, "ietf.org.", dns.rdatatype.DS, True),
                                     msg, False):
            return False

        # check Signed DNAME
        msg = "NO signed DNAME RFC4035"
        if self.register_test_result(9,
                                     self.dname_check(res, "grade.goal.ogud.com.",  dns.rdatatype.TXT, "grade.shinkuro.com.", True),
                                     msg,
                                     False):
            return false;

        # I ask for names that exist but for types that do not
        msg = "Expecting NSEC RFC4305"
        if self.register_test_result(10,
                                     self.negative_check(res, "us.", dns.rdatatype.SPF, True),
                                     msg,
                                     False):   # NSEC signed
            return False

        msg = "Expecting NSEC3 RFC5155"
        if self.register_test_result(11,
                                     self.negative_check(res, "de.", dns.rdatatype.SPF, True),
                                     msg,
                                     False):    # NSEC3 signed
            return False

        # set big buffer size
        res.use_edns(0, dns.flags.DO, 2800)

        big = self.positive_check(res, "shinkuro.net.", dns.rdatatype.A, True)
        msg = "Big UDP answer > 1500 failed bad path?"
        if self.register_test_result(12, big and ( self.get_tc_bit() and self.tcp_works ), msg, False):
            return False

        if not big:
            self.warn_msg = "Link does not support fragmented UDP"

        if self.ad_seen:
            msg = "Bogus returned on badly signed answer"
            if self.register_test_result(13,
                                         self.expect_failure(res, "dnssec-failed.org.", dns.rdatatype.SOA),
                                         msg,
                                         False):
                self.add_reason("returned known bad DNSSEC answer")
                return False

        return True

    def generate_report(self, resolver, submit_report, debug):

        out = "Generate_report: %s %s" % (resolver, submit_report, )
        SResolv = "N/A"

        if (debug):
            self.println(out)

        result = "Test=%s" % (self.string_result(), )
        Resolv = self.addr_lookup(resolver, self.getting_address)
        # use this as an indicator if we can talk directly to resolver
        My_addr = self.addr_lookup(resolver, self.getting_address)  # use dnspython recursive resolver to get own address

        name = (result + ".NS=" + resolver +
                ".Resolv=" + Resolv + ".Me=" + My_addr + ".Version=" +
                self.get_version() + self.user_message.replace(' ', '+'))
        # submit directly to authoritative resolver
        if submit_report:
            rep_ip = self.addr_lookup(resolver, self.submit)
            rep = self.get_resolver(rep_ip, debug=debug)
            if (My_addr == None) or (len(My_addr) < 6):
                rep = get_resolver(null, debug=debug)  # go via recursive resolver

            if rep:
                qname = name  + ".report." + self.zone;
                if debug:
                    self.println("Making query " + qname);
                try:
                    msg = self.make_query(qname, dns.rdatatype.TXT, rep, debug)
                except:
                    self.println("unexpected exception: %s" % (sys.exc_info()[1], ))
                if not msg:
                    self.println("Report failed: " + qname)
                elif len(msg.response.answer) < 1:
                    self.println("Submission error: " + msg)

            if not rep or not msg:
                self.println("Reporting failed: " + name)
                self.reports_failed += 1;
                # how to store for future use ???
            elif self.show_report:
                self.println("Reported result: " + "." + result + " Addr=" + resolver);
        elif debug:
            output = "Result Not submitted: " + name
            self.println(output)
        return name


    def evaluate_resolver(self, resolver, id_msg):
        out = ""
        msg = "Resolver %s" % (resolver, )
        results = "Not a resolver %s" % (resolver, )

        self.reason = ""
        self.report_reset()
        self.set_message(id_msg)

        if self.debug:
            self.println(msg)

        success = self.run_tests(resolver, 14)
        if len(self.reason) and self.detailed_report:
            self.msg += " --> %s" % (self,get_reason(), )

        results = self.string_result()
        if success:
            self.generate_report(resolver, self.submit_report, self.debug)
        elif self.detailed_report:
            results += "  ZZZZ %s" % (msg, )

        if self.debug:
            self.println(results)

        return results

from Translator import Translator
def test():

    debug = False
    
    local_resolvers = DNSSEC_resolver_check.get_local_resolvers()
    print("local resolvers = %s" % (local_resolvers, ))
    
    drc = DNSSEC_resolver_check()
    drc.set_debug(debug)
    tr = Translator(debug=debug)

    def do(nameserver, comment):
        results = drc.evaluate_resolver(nameserver, comment)    
        translation = tr.translate(results)
        print("%s: %s - %s" % (nameserver, results, translation, ))
    
    for res in local_resolvers:
        do(res, "from ogud")

    do('8.8.8.8', "from bob")    
    do('8.8.4.4', "from bob")
    do('4.2.2.2', "from bob")
    #do('192.168.1.5', "from bob")
    
    S = Squery()
    ip_ns1_shkx_org = S.addr_lookup('8.8.8.8', 'ns1.shkx.org')
    do(ip_ns1_shkx_org, "from bob")


    

if __name__ == "__main__":
    test()
