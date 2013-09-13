# 
# Copyright (c) 2012-2013, Shinkuro. Inc
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are
# met: 
#
#    Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.  
#
#     Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

"""
This is a port of UI_DRC.java (ogud@shinkuro.com) to Python

$Id: UI_DRC.py 446 2013-08-16 20:36:10Z bob.novas $
"""

import dns
import sys
from DNSSEC_resolver_check import DNSSEC_resolver_check 
from Translator import Translator

class UI_DRC: 
   def do_eval(resolv, msg, long_report):
      print resolv, msg
      gr = DNSSEC_resolver_check().evaluate_resolver(resolv, msg)
      tr = Translator().translate(gr)
      if (long_report == True): 
         print "Eval: ", resolv, " Tests=", gr, "Result=", tr
      else:
         print "Result: ", resolv, " ", tr
   def usage():
      use_msg = [ "python UI_DRC.py -[adhlrST] [-m <msg>] [<resolvers>]", 
                  "     :  -a # Aborts on first error for each resolver",
                  "     :  -d # prints lots of debug info",
                  "     :  -h # prints help and exits",
                  "     :  -l # Lists the locally configured resolvers and exits",
                  "     :  -r # detailed report on screen", 
                  "     :  -S # DO not SUBMIT results" ,
                  "     :  -T # Show compact from of test results" ,
                  "     :  -m # A string that gets added to the report an identifier",
                  "\tExample: starbucks",
                  "     :    # No resolvers listed, use the configured resolvers",
                  "\tresolvers can be addresses or names" ]

      for i in use_msg:
         print i

   if __name__ == "__main__": 
      num_resolvers = 0
      resolver_evaluated = False
      abort = False
      long_report = False
      msg = False
      message = "Test-x"  #fix later 
      DRC = DNSSEC_resolver_check();
      list = DRC.get_local_resolvers()
      #       print list
      DRC.set_abort(False);
      DRC.set_submit_report(True)
      for i in sys.argv[1:] :
         print i
         if (i == "-a"):
            DRC.set_abort(True)
         elif (i == "-d"):
            DRC.set_debug(True)
         elif (i == "-r"):
            long_report = True;
            DRC.set_verbose_report(long_report)
         elif (i == "-S"):
            DRC.set_submit_report(False)
         elif (i == "-T"):
            DRC.set_show_test_results(True)
         elif (i == "-m"):
            msg = True
         elif (i== "-l"):
            print "Configured resolvers", list
            abort = True
         elif (i == "-h"):
            usage()
            abort = True
         elif( msg == True):
            message = i = message;
            msg = False
         else:
            resolver_evaluated = True
            print "testing", i
            do_eval( i, message, long_report)

         if(abort == True):
            break;

      if( (resolver_evaluated == False) and (abort == False)):
         for j in list:
            do_eval( j, message, long_report)

