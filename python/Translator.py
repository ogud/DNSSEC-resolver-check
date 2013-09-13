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
This is a port of Translator.java (bob@shinkuro.com) to Python

$Id: Translator.py 432 2013-08-15 13:14:04Z bob.novas $
"""

import re

class Translator(object):

    def __init__(self, debug=False):
        self.debug = debug

        self.trans = {}
        self.trans["0"]  = "NAR,1,=Not a Resolver.,0,0"
        self.trans["1"]  = "R=([a-zA-Z]+).*,1a,=*.,0,0"
        self.trans["1a"] = "[FT]............,2,=Not a Resolver.,0,0"
        self.trans["2"]  = ".[PFX][PFX][PFXT][PFX][PF][APFXT][APFXT][APFXT][APFXT][APFXT][APFTXT].,=Unexpected Result.,3,0,0"
        self.trans["3"]  = ".[PF][PF][PF][PF]........,=OLD/Bad.,4,0,0"
        self.trans["4"]  = "PP...P[AP][AP].[AP]...,=Not DNSSEC.,5,0,0"
        self.trans["5"]  = "......PP.P...,7,8,0,0"
        self.trans["7"]  = ".............,7a,=Validator,0,0"
        self.trans["7a"] = "....P...A....,DNAME,7b,1,0"
        self.trans["7b"] = "...F.......A.,7c,TCP,0,0"
        self.trans["7c"] = "............F,7d,Permissive,0,0"
        self.trans["7d"] = "......[AFTX][AFTX][AFTX][AFTX][AFTX][AFTX].,Mixed,6a,0,1"
        self.trans["8"]  = ".............,8a,=DNSSEC Aware,0,0"
        self.trans["8a"] = "....P...[AP]....,DNAME,8b,0,0"
        self.trans["8b"] = "...F.......[AP].,6a,TCP,0,0"
        self.trans["6a"] = "..F..........,6b,Unknown,0,0"
        self.trans["6b"] = "..........F..,6c,NSEC3,0,0"
        self.trans["6c"] = "...P.......[XTF].,6d,SlowBig,0,0"
        self.trans["6d"] = "...F.......[XTF].,.,NoBig,0,0"
        self.trans["."]  = ".............,.,.,0,0"

    def set_debug(self, val):
        self.debug = val

    def translate(self, pfa):
        g = ""
        gmod = ""
        inhibits = 0

        next_state = "0"
        while next_state != ".":
            p = self.trans.get(next_state)
            pieces = p.split(",")
            if len(pieces) == 5:
                # pattern, fail, succeed
                # fail/succeed: transition | [=]output[.]
                # = means main ("g"), no = means within ()'s ("gmod")
                # . is terminal

                pattern = re.compile(pieces[0])
                set_inhibits = int(pieces[3])
                mbz_inhibits = int(pieces[4])

                state = next_state
                next_state = "NOT_A_STATE"

                m = 0
                matcher = pattern.match(pfa)
                match_action = alt_action = ""

                if (inhibits & mbz_inhibits) != 0:
                    # this is useful only to inhibit "Mixed" when "DNAME"
                    # and unfortunately "Mixed" uses negative logic
                    # so the match is backwards, ...
                    # not very general purpose, but the best I could come up with.
                    match_action = pieces[2]
                    alt_action = pieces[1]
                elif matcher:
                    m = 1
                    match_action = pieces[2]
                    alt_action = pieces[1]
                else:
                    # oddly, set the really special purpose inhibits on the negative match
                    inhibits |= set_inhibits
                    match_action = pieces[1]
                    alt_action = pieces[2]

                if self.debug:
                    print("state=%-2s, inhibits=%x p=%s, pfa=%s, match=%s, match_action=%s, alt_action=%s, g=%s, gmod=%s" %
                        (state, inhibits, p, pfa, m, match_action, alt_action, g, gmod, ))

                if match_action in self.trans:
                    next_state = match_action
                    continue
                else:
                    have_dot = "." in match_action and match_action.index(".")
                    if have_dot:
                        match_action = match_action[0:have_dot]

                    if match_action.startswith("="):
                        g = match_action[1:]
                        if g == "*":
                            g = matcher.group(1)
                    else:
                        gmod = gmod + match_action + ","

                    if have_dot > 0:
                        next_state = "."
                    else:
                        next_state = alt_action
            else:
                print("ERROR-BadPattern: p=%s, next_state=%s", (p, next_state, ))
        if len(g) == 0:
            g = "NAR"
            print("ERROR: pfa=%s, g=%s", (pfa, g, ));
        else:
            l = len(gmod)
            if l > 0:
                g = "Partial " + g + "(" + gmod[0:l-1] + ")"
        return g



def test():
    tr = Translator(debug=False)

    b = tr.translate("PPPPPPAAPAAAP")
    print("Expect Partial Validator(DNAME), b=" + b)

    b = tr.translate("PPPPPPPPPPPPP")
    print("Expect DNSSEC Aware, b=" + b)

    b = tr.translate("PPPPPPAPAPAAP")
    print("Expect Partial Validator(Mixed), b=" + b)

    b = tr.translate("PPPPPPAAAAFAA")
    print("Expect Partial Validator(NSEC3), b=" + b)

    b = tr.translate("PPPPPPAAAAAAF")
    print("Expect Partial Validator(Permissive), b=" + b)

    b = tr.translate("PPPFPPAAAAAAA")
    print("Expect Partial Validator(TCP), b=" + b)

    b = tr.translate("PPFPPPAAAAAAA")
    print("Expect Partial Validator(Unknown), b=" + b)

    b = tr.translate("PPPPFPAAAAAAF")
    print("Expect Partial Validator(DNAME,Permissive), b=" + b)

    b = tr.translate("PPPPPPAAAAAFA")
    print("Expect Partial Validator(SlowBig), b=" + b)

    b = tr.translate("PPPFPPAAAAAFA")
    print("Expect Partial Validator(NoBig), b=" + b)

    b = tr.translate("PPPPPPAAAAAAA")
    print("Expect Validator, b=" + b)

if __name__ == "__main__":

    test()
