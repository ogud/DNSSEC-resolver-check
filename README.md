About DNSSEC-resolver-check
===========================

This project consists of DNSSEC-resolver-check, implemented in java, and 
pyDRC, a subset of DNSSEC-resolver-check, implemented in python.

java
----
DNSSEC-resolver-check (the java code) is a set of java classes that implement
an application that evaluates how well a resolver supports DNSSEC as seen from 
the location at which the applicaiton runs. 

The evaluation is submitted to a central server operated by us. 

This collection depends on dnsjava 
please put a recent dnsjava jar file (>2.1.3) in the current directory
and update the Makefile to reflect it. 

Usage of command line tool: UI_DRC
----------------------------------

         java UI_DRC <options> <resolver candidates> 
    or   java -jar UI_DRC-0.5.5.jar <options> <resolver candidates> 
         options: 
          -a # Aborts on first error for each resolver
          -d # prints lots of debug info
          -h # prints help and exits
          -l # Lists the locally configured resolvers and exits
          -r # detailed report on screen
          -S # DO not SUBMIT results
          -T # Show compact from of test results
          -m <string> # A string that gets added to the report as an identifier 
   	Example: starbucks
             #  No resolvers listed, use configured resolvers
      resolvers can be addresses or names

New report format:

    Tests=<str>.NS=<ip1/name>.Resolv=<ip2>.Me=<ip3>.Version=<str>.Msg=<str>.submit.dnssecready.net

    Tests= <str>      reports the result of the 13 tests 
    NS=<ip1/name> 	   is the name or address being tested 
    Resolv=<ip2> 	   is the IP address the resolver reports for itself 
    Me=<ip3>  	   is the public IP address my servers see 
    Version=<string>  The version of the test program 
    Msg=<string>	   An indicator where the test was performed (optional) 
 

The DRC Applet and Server
=========================

The Applet and javascript can be served by a php server, if the following files are
present:

   - dnsjava-2.1.4.jar             (dns stub forwarder, MUST BE SIGNED)
   - DNSSEC_Check_Help.php         (content of the hover text help for behaviors)
   - DNSSEC_Check_Test_Help.html   (content of the help for the tests)
   - DSC-3.php                     (the main php file that outputs the GUI)
   - lc.min.js                     (a jquery control used by the GUI)
   - UI_DRC-0.5.5.jar              (the main DRC class jar, MUST BE SIGNED)
   - DNSSEC_Check-1.0.2.jar        (the applet jar, MUST BE SIGNED)
    
If all these files are present in a php server folder, and you point a browser at DRC-3.php,
you should get the DRC web page.


python
------
The python code is a set of python classes that implements the DNSSEC-resolver-check
functionality as a library, along with a simple, console user interface. See UI_DRC.py
for usage.