This is a java application that evaluates how well a resolver supports DNSSEC
as seen from the location that the applicaiton runs. 

The evaluation is submitted to a central server operated by us. 

New report format: 
 Tests=<str>.NS=<ip1/name>.Resolv=<ip2>.Me=<ip3>.Version=<str>.Msg=<str>.submit.dnssecready.net

 Tests= <str>      reports the result of the 13 tests 
 NS=<ip1/name> 	   is the name or address being tested 
 Resolv=<ip2> 	   is the IP address the resolver reports for itself 
 Me=<ip3>  	   is the public IP address my servers see 
 Version=<string>  The version of the test program 
 Msg=<string>	   An indicator where the test was performed (optional) 




