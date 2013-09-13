# #######################################################################
# Copyright (c) 2012, Bob Novas, Shinkuro, Inc.
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
Constant definitions

$Id: constants.py 430 2013-08-15 12:15:01Z bob.novas $
"""

class DRC_Exception(Exception):
    """base class for all validator raised exceptions"""
    pass

class BadResult(DRC_Exception):
    """a result did not meet the behavior specified"""
    def __init__(self, actualResult):
        self.actualResult = actualResult

class BadSigner(DRC_Exception):
    """an RRSIG RRset had differing signers"""
    pass

class CnameRedirection(DRC_Exception):
    """a CNAME redirection was encountered"""
    def __init__(self, originalName, targetName):
        self.originalName = originalName
        self.targetName = targetName

class DnameRedirection(DRC_Exception):
    """a DNAME redirection was encountered"""
    def __init__(self, originalName, targetName):
        self.originalName = originalName
        self.targetName = targetName

class FailedValidation(DRC_Exception):
    """validation failed for the given reason"""
    def __init__(self, reason):
        self.reason = reason

class InconsistentRRset(DRC_Exception):
    """an inconsistent RRset was encountered"""
    pass

class NoRRSig(DRC_Exception):
    """no RRSIG set found covering a given RRset"""
    def __init__(self, reason):
        self.reason = reason

class ServFail(DRC_Exception):
    """hit a servfail condition"""
    def __init__(self, reason):
        self.reason = reason

class NegativeProofResult(DRC_Exception):
    """
    a negative was proved -
    rdtype does not exist for name with given outcome
    """
    def __init__(self, name, rdtype, outcome):
        self.name = name
        self.rdtype = rdtype
        self.outcome = outcome

class NoKeys(DRC_Exception):
    """
    no keys found for the signer
    """
    def __init__(self, reason):
        self.reason = reason

class UnknownOutcome(DRC_Exception):
    """
    Probably a failure of the algorithm - something happened
    that the algorithm didn't handle.
    """
    def __init__(self, reason):
        self.reason = reason
