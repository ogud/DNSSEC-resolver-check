
This is a set of java classes application that evaluates how well a
resolver supports DNSSEC as seen from the location that the applicaiton runs. 

The evaluation is submitted to a central server operated by us. 

This collection depends on dnsjava 
please put a recent dnsjava jar file (>2.1.3) in the current directory
and update the Makefile to reflect it. 

Usage of command line tool: UI_DRC 
      java UI_DRC <options> <resolver candidates> 
or    java -jar UI_DRC-0.5.5.jar <options> <resolver candidates> 
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




