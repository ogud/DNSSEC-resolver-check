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
RRSetSource class for validating stub resolver

$Id: rrSetSource.py 430 2013-08-15 12:15:01Z bob.novas $
"""

import dns
from dns.rdtypes.ANY.RRSIG import RRSIG
from constants             import NoRRSig, InconsistentRRset

class RRSetSource(object):
    """Holds a section or collection of RRset resources such as the answer,
    authority or additional section of a response and provides iterator and
    other services on that collection."""

    class _iterator(object):
        """
        iterator for RRSetSource, allows multple iterators to run concurrently
        """

        def __init__(self, source):
            self._source = source
            self._inx = 0
            self._len = len(source.get_section())

        def next(self):
            """
            return the next rrset, rdtype, rdclass tuple in the source
            """
            if self._inx >= self._len:
                raise StopIteration
            rrset = self._source.get_section()[self._inx]
            self._inx += 1
            rdtype, rdclass = self._source.analyze_rrset(rrset,
                                                         check_consistency=False)
            return rrset, rdtype, rdclass

    def __init__(self, section):

        self._section = section

        #make a dictionary of rrsig rrsets keyed by (name, covered rdtype, rdclass)
        #this will also check the consistency of all of the rrsets
        self._rrsig_dict = self._make_rrsig_dict()

        #de-duplicate self._rdtypes for efficiency
        self._rdtypes = []
        for rrset, rdtype, rdclass in self:
            if rdtype not in self._rdtypes:
                self._rdtypes.append(rdtype)
        self._rdtypes.sort()

        #for testing if a source contains an rrset with a synthesized CNAME (ttl = 0)
        self._non_synth_cname_rdtype = \
            [rdtype for rrset, rdtype, rdclass in self
             if rdtype == dns.rdatatype.CNAME and rrset.ttl != 0]

    def __iter__(self):
        return self._iterator(self)

    def __repr__(self):
        return ', '.join(['%s(%d)'% (dns.rdatatype.to_text(rdtype), len(rrset), ) for rrset, rdtype, rdclass in self])

    @staticmethod
    def analyze_rrset(rrset, check_consistency=True):
        """
        Analyze an rrset and return its type and class.
        Optionally checks if the rrset is consistent.
        Raises InconsistentRRset if the rrset is not consistent,
        e.g., if it does not contain homogeneous RRs.
        """
        if rrset:
            rr0_rdtype = rrset[0].rdtype
            rr0_rdclass = rrset[0].rdclass
            if check_consistency:
                for rr in rrset[1:]:
                    if rr.rdtype != rr0_rdtype or \
                       rr.rdclass != rr0_rdclass:
                        raise InconsistentRRset
            return rr0_rdtype, rr0_rdclass
        else:
            return None, None

    def get_section(self):
        """
        get accessor for the private _section (used by the iterator)
        """
        return self._section

    def find_covering_rrsigset(self, rrset, raiseExc=False):
        """
        return an rrset with the same name, type and class from the
        self._rrsig_dict
        """
        key = (rrset.name, rrset.rdtype, rrset.rdclass)
        if key in self._rrsig_dict:
            return self._rrsig_dict[key]
        elif raiseExc:
            raise NoRRSig('no RRSiG found for key: %s' % (key, ))
        else:
            return None

    def has_NSEC(self):
        """return if the source contains NSEC rrsets"""
        return dns.rdatatype.NSEC in self._rdtypes

    def has_NSEC3(self):
        """return if the source contains NSEC3 rrsets"""
        return dns.rdatatype.NSEC3 in self._rdtypes

    def has_DNAME(self):
        """return if the source contains DNAME rrsets"""
        return dns.rdatatype.DNAME in self._rdtypes

    def has_CNAME(self):
        """return if the source contains CNAME rrsets"""
        return dns.rdatatype.CNAME in self._rdtypes

    def has_CNAME_non_synthesized(self):
        """return if the source contains non synthesized CNAME rrsets,
        e.g., CNAMES with non-zero ttl"""
        return not not self._non_synth_cname_rdtype

    def has_DS(self):
        """return if the source contains a DS rrset"""
        return dns.rdatatype.DS in self._rdtypes

    def has_RRSIG(self):
        """return if the source contains an RRSIG"""
        return dns.rdatatype.RRSIG in self._rdtypes

    def count(self, count_rdtype):
        """count the number of count_rdtype RRs in the source"""
        n = 0
        for rrset, rdtype, rdclass in self:
            if rdtype ==  count_rdtype:
                n += len(rrset)
        return n

    def get_rrset(self, find_rdtype):
        """get an rrset by type - dangerous, since this only
        gets the first such rrset, there may be more than one"""
        for rrset, rdtype, rdclass in self:
            if rdtype == find_rdtype:
                return rrset
        return None

    @staticmethod
    def is_synthetic_CNAME(rrset):
        """returns if the rrset contains a synthetic CNAME"""
        return rrset.rdtype == dns.rdatatype.CNAME and rrset.ttl == 0

    def _make_rrsig_dict(self):
        """construct a dict of rrsigs keyed by (name, covered type, class)"""
        rrsig_dict = {}
        for rrset in self._section:
            rdtype, rdclass = self.analyze_rrset(rrset, check_consistency=True)
            if rdtype == dns.rdatatype.RRSIG:
                assert isinstance(rrset[0], RRSIG)
                name = rrset.name
                rrsig_dict[(name, rrset[0].type_covered, rdclass)] = rrset

        return rrsig_dict
