// Copyright (c) 2013 Shinkuro INC 
// Date: Feb 2013 
// 

/** @author Olafur Gudmundsson &lt;ogud@shinkuro.com&gt; */
/* Licence BSD */ 
/* This library/module asks questions of a resovler candidate and reports back
   what the result of the questions where. 
   the main method is evaluate_resolver(String)
   it returns back a string of results of the form: 
   [AFPTX]*[R=<code>] 
   F = Test failed 
   P = Test passed
   A = Test passed with AD bit set as expected 
   T = Timeout or error 
   X = Test passed but with AD bit set when not possible or requested.
   R = Test got an error code from resolver =<code> reflects that code

   Other methods that can be invoked are:
   set_abort(boolean)  tells the test functions to stop after first 
         non-expected result only use for debugging 
   set_show_test_results(boolean) D:off prints to standard output what 
        is sent to central report server 
   set_submit_report(boolean) turn [D:on]/off submitt reprot 

   set_debug(boolean) turn [D:off]/on lots of debug output

   set_verbose_report(boolean) turn [D:off]/on more detail on each test 

   set_message(string) adds a message to the submission 

   This program reqires the DNSjava library tested with version 2.1.
*/

import java.io.*;
import java.net.*;
import org.xbill.DNS.*;

public class DNSSEC_resolver_check  extends Version {
    // global variables 
    static boolean abort = false;
    static boolean debug = false;   
    static boolean submit_report = true;
    static boolean show_report = false;
    static boolean init_done = false;
    static boolean detailed_report = false;
    static int reports_failed = 0;
    static int tests_run = 0;
    static String reason = "";  // error state 
    static boolean ad_current = false;  // AD seen or not 
    static int ed_buff = 2048;  // size of answers we accept
    static boolean ad_seen, big_ok, saw_timeout; 
    static int response_size;
    static boolean tcp_works = false;
    static String  warn_msg = "";
    static boolean failed_test = false;
    static boolean test [] = new boolean[14];
    static boolean test_performed [] = new boolean [14];
    static boolean ad_res[] = new boolean[14];
    static boolean timeout[] = new boolean[14];
    static boolean timeout_is_failure [] = new boolean[14];
    static String test_msg [] = new String[14];
    static int    test_size [] = new int[14]; 
    static String test_name [] = new String[14]; 
    static String zone = "submit.dnssecready.net.";
    static String getting_address = "whatsmyip." + zone;
    static String submit = "report.shinkuro.com.";

private static void 
init_variables()  {
    int i=0;
    test_name[0] = "None";
    timeout_is_failure[0] = true;
    test_name[1] = "Recursive Resolver";  //1 
    timeout_is_failure[1] = true;
    test_name[2] = "EDNS0 Support";       //2 
    timeout_is_failure[2] = true;
    test_name[3] = "RFC3597/Unknown Support"; //3 
    timeout_is_failure[3] = true;
    test_name[4] = "TCP support";        //4
    timeout_is_failure[4] = true;
    test_name[5] = "DNAME Support";      //5
    timeout_is_failure[5] = true;
    test_name[6] = "Large UDP";          //6
    timeout_is_failure[6] = true;
    test_name[7] = "DO support + RRSIG in answer"; //7
    timeout_is_failure[7] = false;
    test_name[8] = "DS found";           //8
    timeout_is_failure[8] = false;
    test_name[9] = "Signed DNAME";       //9
    timeout_is_failure[9] = false;
    test_name[10] = "NSEC seen";          //10
    timeout_is_failure[10] = false;
    test_name[11] = "NSEC3 seen";         //11
    timeout_is_failure[11] = false;
    test_name[12] = "Big Signed";         //12
    timeout_is_failure[12] = false;
    test_name[13] =  "Returns Bogus";     //13
    timeout_is_failure[13] = false;
    init_done = true;
}

  /* Standardt output function */
static void 
print (Object o) {
    System.out.println(o); 
}
    
  /* convert from Sting to Name (DNS format) 
   * hide exceptions (that should not happen)
   */
private static Name 
Str_to_Name( String na) {
    Name my_name = null;
    try { 
 	my_name = Name.fromString(na, Name.root);
    } catch (Exception e) {
 	reason = reason + "Name error rrsig_check " + na;
 	my_name = null;
    }
    return my_name;
}
  /* the upcoming set of functions all set flags, this is done to allow
   * applets and other extenders of the class to set various variables. 
   */
public static void 
set_abort(boolean val) {
    abort = val;
}

public static void
set_show_test_results(boolean val){
    show_report = val;
}

public static void 
set_submit_report(boolean val) {
    submit_report = val;
}

public static void 
set_debug(boolean val) {
    debug = val;
}

public static void 
set_verbose_report(boolean val) {
    detailed_report = val;
}

  /* Now functions related to AD bits all internal 
   */

private static void 
ad_reset() {
    ad_seen = false;    // no evidence of AD yet
    ad_current = false;  // add seen in this query 
}


// I expected AD on this answer check if it was correct
private static void 
ad_add(boolean val) {
    ad_current = val; 
    if (val == true)      // good 
 	ad_seen = val;   // highest AD setting seen
}

  /* this function resets all tracking variables between tests */
private static void 
report_reset() {
    int i;
    if (init_done == false) 
	init_variables();
    for (i = 0; i < test.length; i++) {
	test_performed[i] = test[i] = ad_res[i] = timeout[i] = false;
	test_msg[i] = null;
	test_size[i] = 0;
    }
    tests_run = 0;
    saw_timeout = false;
    failed_test = false;
}
    /* record test results 
     * returns true if tests failed and stop should be considered here. 
     *  in all other cases it returns false 
     * Inputs: 
     *     result : the result of the test_function 
     *     msg    : the error message for this test 
     *     bad    : what is the wrong value for result 
     */ 
private static boolean
register_test_result(int test_number, boolean result, String msg, 
		     boolean bad) {
  //  print( (String) "Registering " + test_number + result + bad);
    test_performed[test_number] = true;
    timeout[test_number] = saw_timeout;
    tests_run++;
    ad_res[test_number] = ad_current;
    ad_current = false;  // reset for next test 
    test_size[test_number] = response_size;
    test_msg[test_number] = msg + " -- " + reason; 	// record message 
    if (result == bad) {   		// handle failed test 
 	failed_test = true;		// 
 	reason = "";                    // reset reason ?? XXX
 	return abort;    
    }
    test[test_number]  = true;      // got expected result ? 
    return false;
}

void 
display_result() {
    print(reason);
}
    /* this function returns the letter reflecting the result of the test */

static String 
test_letter(int i) {
    String letter = "Y";
    if (test_performed[i] == false) 
	letter = "S"; // Skipped 
    else if (timeout[i] == true && timeout_is_failure[i] == false) 
        letter = "T";
    else if (test[i] == true) 
	if (ad_res[i] == true)    letter = "A"; // Passed with AD set 
	else	    		  letter = "P"; // Passed 
    else 
	if (ad_res[i] == false)   letter = "F"; // Failed 
	else   	                  letter = "X"; // Failed with AD set BAD
    return letter;
}

    // Function to output results returns a message of results 
static String
test_results() { 
    String out = ""; // Summary line 
    if (failed_test) {
 	// First report on each test 
	int i;
	String rep = ""; // Explanation of failed tests
 	for (i = 1; i < test.length; i++) {
 	    out = out + " T" + (i) + test_letter(i) + "/" + test_size[i];
	    if (test_performed[i] == false) 
		rep = rep + " T" + (i) + " " + test_name[i] + 
		    " := Skipped\n" ;
	    else if (test[i] == false) { // failed 
 		if (test_msg[i] != null) 
 		    rep = rep + " T" + (i) + " " + test_name[i] 
 			+ " := " + test_msg[i] + "\n";
 	    }
 	} 
 	if (detailed_report) 
 	    out = out +"\nFailed tests:\n" + rep ;
	// 	else 
	// 	    out = "";
    } else if (tests_run > 1) 
 	out = "All tests passed";
    else 
        out = "No Tests Run";
    return out;
}

    // function to return the string result of all the tests
static String 
string_result() {
    int i; 
    String out = "";
    for (i=1; i < test.length; i++) {
	out = out + test_letter(i);
    }
    return out;
}    

    // this function gets passed in an array of records from one section 
    // it will count the number of records of the specified type 
    //
static int 
count_rr(Record ca[], Name na, int type) { 
    int i, cnt = 0;
    Name nn = null;
    String str;
    if (debug) {
 	str = "Count_rr start " + na + " type=" + Type.string(type) + " size=" 
	    + ca.length;
 	print (str);
    }
    for (i = 0; i < ca.length; i++) {
 	if (debug)
 	    nn = ca[i].getName();  // DO I realy need names ?? OGUD 
 	if (ca[i].getType() == type) {
	    cnt++; 
	    if (debug) {
		str = "count_rr loop i=" + i + " type=" + ca[i].getType() + 
		    " cnt=" + cnt;
		print (str);
	    }
 	}
    }
    if (debug) {
 	str = "count_rr END" + ca.length + " " + nn + " == " + na + 
 	    " type=" + Type.string(type) + " cnt=" + cnt;
 	print(str);
    }
    return cnt;
}

     /* make_query() a simple query interface that catches exceptions 
      *      when there is an error it returns a null object 
      *      hides exceptions from main program 
      *  Arguments: domain: the domain name to look up
      *             type: the type of the record to lookup
      *             res: The resolver to use
      */
private static Message 
make_query( String domain, int type, SimpleResolver res) {
    Message query, response;
    Name name;
    int dclass = DClass.IN;
    response_size = 0;
    saw_timeout = false;
    if ((name = Str_to_Name(domain)) == null) 
 	return null;
    
    Record rec = Record.newRecord(name, type, dclass);
    try {
 	query = Message.newQuery(rec);
    } 
    catch (Exception e) {
 	reason = reason + "Query Construction Error " + domain + " " + 
	    Type.string(type);
	if (debug) 
	    print (reason);
 	return null;
    }

    try { 
 	response = res.send(query);
    }
    catch (SocketTimeoutException t) {
      if (debug) {
	print ("catching Timeout exception");
      }
      reason = reason + "Timeout";
      saw_timeout = true;
      return null;
    }
    catch (Exception e) {
      	reason = reason + "Lookup failed: "; 
	if (debug) {
	  print ("catching socket exception: " + e);
	  reason = reason + e;
	  //	  print (reason);
	}
 	return null;
    }

    response_size = response.numBytes();

    if (debug)  {
 	String size= " Size " + domain + " " + Type.string(type) + " " 
 	    + response.numBytes();
 	print(size);
    }
    return response;
}
    
    /* first_check is used to check minimal resolver behavior 
       this function tries to catch all errors and exceptions
       as well as detecting when this is not a recursive resolver
       
       Arguments: res == Resolver object 
      	 domain == name to be looked up 
	 qtype  == the type to ask for 
	 edns   == check if edns is included
       Returns: false if failure otherwise true. 
    */
private static boolean
first_check( SimpleResolver res, String domain, int qtype, boolean edns) {
    Message query, response;
    response =  make_query(domain, qtype, res); 
    if (response == null) 
 	return false; // failed 
    ad_add(response.getHeader().getFlag(Flags.AD)); // log ad bit 

    if (debug)
 	print (response);
    if (response.getRcode() != Rcode.NOERROR) { 
 	reason = reason + " DNS Error " + Rcode.string(response.getRcode());
 	return false;
    }
    if (!(response.getHeader().getFlag(Flags.RA))) {
 	reason = reason + " Error Not a recursive resolver RA flag missing ";
 	return false;
    }
    Record Ans [] = response.getSectionArray(Section.ANSWER);
    
    Name name = Str_to_Name(domain);
    if(count_rr(Ans, name, qtype) == 0) {
 	reason = reason + " No " + Type.string(qtype) + " seen in answer "; 
 	return false;
    }

    if (edns) {
 	OPTRecord ORec = response.getOPT();
 	int size = response.numBytes();
 	if (ORec == null)  {
 	    reason = reason + " No Opt returned ";
 	    return false;
 	} else if( size > 512) { 
 	    big_ok = true;
 	} else if (ORec.getPayloadSize() < size) {
 	    reason = reason + " Small ENDS reported " + 
	      ORec.getPayloadSize() + " < " + size;
	    // not a failure 
 	    //	    return false;
 	}
    }
    return true;
}

    /* perfrom checks that the resolver does the right thing for DNAME's 
       Arguments resolver, domain name and type 
       IN addition we have target which is what we expect the final answer 
       to be */

static boolean 
dname_check( SimpleResolver res, String domain, int type, String target,
	     boolean count_rrsig) {
    Message response;
    if ((response = make_query(domain, type, res)) == null) {
 	reason = reason + "DNAME lookup failed ";
 	return false;
    }
    else if (debug) 
 	print(response); 
    ad_add(response.getHeader().getFlag(Flags.AD)); // log ad bit 

    int cnt = response.getHeader().getCount(Section.ANSWER);
    
    if (cnt  <= 0) {
 	reason = reason + "Empty DNAME Answer ";
 	return false;
    } 
    
    //
    // make sure the answer contains some DNAME's 
    // if not the resolver is not DNAME compliant 
    //
    Name name = Str_to_Name(domain);
    Record Ans [] = response.getSectionArray(Section.ANSWER);
    
    if(count_rr(Ans, name, Type.DNAME) == 0) {
 	reason = reason + " NO DNAME seen in answer "; 
 	return false;
    }
    
    if (count_rrsig) {
 	if (cnt < 2) { // DNAME and target RRset are signed 
 	    reason = reason + "Not enough records in DNAME answer " + cnt;
 	    return false ; 
 	} else if ((Ans[1].getType() != Type.RRSIG)) {
 	    reason = reason + " Missing RRSIG(DNAME)"; 
 	    return false;
 	} else { 
 	    int tt = ((RRSIGRecord) Ans[1]).getTypeCovered();
 	    if (tt != Type.DNAME) {
 		reason = reason + " Wrong RRSIG(" + Type.string(tt) + 
		    ")expecting RRSIG(DNAME)";
 		return false;
 	    }
 	}
    }
    
    // check that the final name in the answer section matches 
    // the name we are expecting
    String res_target = Ans[Ans.length - 1].getName().toString();
    if (target.equals(res_target))
 	return true;
    reason = reason + " Dname name mismatch " + target + " != " + res_target;
    return false;
}


static boolean
empty_answer( Message msg) {
    int cnt = msg.getHeader().getCount(Section.ANSWER);
    if (cnt <= 0) {
 	return true;
    }
    return false;
}
    
static Message
response_ok(SimpleResolver res, String domain, int type) {
    Message response = make_query(domain, type, res); 
    if (response == null) 
 	return null;
    if (debug) 
 	print(response); 
    ad_add(response.getHeader().getFlag(Flags.AD)); // log ad bit 

    if (response.getRcode() != Rcode.NOERROR) {
 	reason = reason + " RCODE=" + response.getRcode();
 	return null;
    }
    return response;
}

    // asking for a name that will fail validation 

static boolean 
expect_failure( SimpleResolver res, String domain, int type) {
    String rrr = reason; 
    Message response = response_ok(res, domain, type);
    if (response == null) {
 	reason = rrr; // restore to prior state
 	return true;
    } else { 
        Name my_name = Str_to_Name(domain);
        Record Ans[] = response.getSectionArray(Section.ANSWER);
        int so = count_rr(Ans, my_name, type);
	int rsig = count_rr(Ans, my_name, Type.RRSIG);
 	print((String) "expect_failure " + domain + " " + Type.string(type) 
	      + " Got: " + Rcode.string(response.getRcode()) +  
	      " != SERVFAIL " + "#" + Type.string(type) + " " + so 
	      +  " #RRSIG " + rsig);
	if (debug) 
	  print(response); // not the whole packet need to parse it 
	
    }
    return false;
}
static boolean is_tc_set = false;

static boolean 
bit_tc_set() {
    return is_tc_set; 
}

static void 
bit_tc_clear() {
    is_tc_set = false;
}

static boolean 
bit_tc_set( boolean val) {
    is_tc_set = val;
    return val;
}

static boolean
positive_check( SimpleResolver res, String domain, int type, boolean ad) {

    bit_tc_clear();
    Message response = response_ok(res, domain, type);
    if (response == null) 
 	return false; 
    int i = 0;
    bit_tc_set(response.getHeader().getFlag(Flags.TC));

    if (empty_answer(response) == true) {
 	reason = reason + "Empty Answer:" + domain + " " + Type.string(type)
	    + " ";
 	return false; 
    }
    
    Record Ans[] = response.getSectionArray(Section.ANSWER); 
    if (Ans.length == 0) {
 	reason = reason + " Empty answer " + domain + " " + Type.string(type);
 	return false;
    }

    
    while( (i < Ans.length) && (Ans[i].getType() == type))
 	i++;
 
    if (i == 0) { //  did not find what I expected
 	reason = reason + " Expected " + domain + " " + Type.string(type);
 	return false;
    }

    if ( (i >= Ans.length) || (Ans[i].getType() != Type.RRSIG)) { 
	reason = reason + " Missing RRsig " + domain + " " + Type.string(type); 
	return false; 
    }
    return true; 
}

     // checks if DNSSEC negative answer is proper
static boolean 
negative_check( SimpleResolver res, String domain, int type, boolean ad) {
    Message response;
    Name my_name; 
    if((my_name = Str_to_Name(domain)) == null)
 	return false;
    
    response = response_ok(res, domain, type);
    if (response == null) 
 	return false; 
    
    if (empty_answer(response) == false) {
 	reason = reason + " Answer != empty " + domain + " " + 
	    Type.string(type);
 	return false; 
    }
    
    Record Auth[] = response.getSectionArray(Section.AUTHORITY);
    if (Auth.length == 0) { // empty authority 
 	reason = "Empty negative answer";
 	return false;
    } else if (count_rr(Auth, my_name, Type.SOA) > 0){ 
	// must be backwards compatibility
	// Now count the records that I expect to find in the authority seciton 
 	int n  = count_rr(Auth, my_name, Type.NSEC); // either NSEC or NSEC3 
 	int n3 = count_rr(Auth, my_name, Type.NSEC3); // must be there
 	if ( ((n >  0) && (n3 == 0)) || ((n == 0) && (n3 >  0))){  
 	    // make sure there are NSEC or NSEC3 but not both
 	    int x = count_rr(Auth, my_name, Type.RRSIG); // signatures present ?
 	    if ( x > 1)  // at least SOA and one NSECx record must be signed 
		return true; 
	    else
		reason = reason + " Not enough RRSIG " + x + " ";
 	} else
	    reason = reason + " Missing NSEC/NSEC3 " + n + " " + n3 ;
    } 
    return false; 
}


    /* dnssec_tests() performs all the tests that see if an app can validate 
     * behind this resolver 
     */
static boolean
dnssec_tests(SimpleResolver res) {
    String msg;
    res.setEDNS(0, ed_buff, ExtendedFlags.DO, null);
    ad_reset();
    //
    // check if I get validated answer for SOA records

    if (register_test_result(7, positive_check( res, "iab.org.", Type.SOA, true),
 			      msg = "No Signed SOA RFC4035", false))
 	return false; 
    
    // Now check if I can get a DS record
    // 
    if (register_test_result(8, positive_check( res, "ietf.org.", Type.DS, true),
 			     msg = "no DS recieved RFC4035", false)) 
 	return false; 

    
    // check Signed DNAME 
    if (register_test_result(9, dname_check( res, "grade.goal.ogud.com.", 
					     Type.TXT, "grade.shinkuro.com.", 
					     true), 
 			     msg = "NO signed DNAME RFC4035" , 
 			     false))
 	return false; 
    
    // I ask for names that exist but for types that do not 
    if (register_test_result( 10, negative_check( res, "us.", Type.SPF, true),
			      msg = "Expecting NSEC RFC4305", 
 			      false))   // NSEC signed 
 	return false;

    
    if (register_test_result( 11, negative_check(res, "de.", Type.SPF, true),
 			      msg = "Expecting NSEC3 RFC5155", 
 			      false))  //NSEC3 signed
 	return false; 
    
    // set big buffer size 
    res.setEDNS(0, 2800, ExtendedFlags.DO, null);
    //
    // Logic if I can get big answer either by UDP or TCP that is fine 
    // if UPD 
    boolean big = positive_check(res, "shinkuro.net.", Type.A, true);
    /*
     * cases
     *      big == true => pass 
     *      big == false && tcp_works == false => fail 
     *      big == false  && tcp_works == true  => test 
     */
    if (register_test_result( 12, big || (bit_tc_set() & tcp_works),
 			      msg = "Big UDP answer > 1500 failed bad path?", 
 			      false))
 	return false;

    if (big == false) { 
	// UDP Small  do I warn about that 
	warn_msg = "Link does not support fragmented UDP";
    }

    if (ad_seen) { 
	if (register_test_result( 13, expect_failure(res, 
						 "dnssec-failed.org.", 
						 Type.SOA),
			      "Bogus returned on badly singed answer",
			      false)) {
	    reason = reason + " returned known bad DNSSEC answer "; 
	    return false;
	}
    }
    
    return true;
}

static SimpleResolver
get_resolver( String resolver){
    SimpleResolver tcp; 
    try {
      if (resolver != null) 
	tcp = new SimpleResolver(resolver);
      else 
	tcp = new SimpleResolver();
    } catch (Exception e) {
      	reason = reason + " Can not create resolver ";
	if (debug) 
	  reason = reason + e;
 	return null;
    }
    return tcp;
}

private static boolean
tcp_test(String resolver) {
    SimpleResolver tcp; 
    tcp_works = false;
    if ((tcp = get_resolver(resolver)) == null)
	return false;

    tcp.setTCP(true);
    if (first_check(tcp, "net.", Type.SOA, false) == false) {
 	reason = reason + "TCP not offered"; 
 	return false; 
    }
    tcp_works = true;
    return true;
}

    // runs all the tests for one resolver input name or address of resolver
private static boolean 
run_tests( String resolver, int fail_allowed) {
    big_ok = false;
    SimpleResolver res = get_resolver(resolver);
    String msg = null;
    if (res == null) {
 	reason = reason + " Can not create resolver"; 
 	return false;
    }
    res.setTCP(false); // do not fall back to tcp
    res.setIgnoreTruncation(true);
    
    // does it answer questions 
    boolean first_one = first_check(res, "com.", Type.SOA, false);
    if (register_test_result(1, first_one, 
		    msg = "Can't resolve com. soa not a useful resolver ", 
 			      false))
 	return false;  // not a resolver abort 
    if (first_one == false)  // force stop if this one fails 
 	return false;

    // check for old DNS extensions
    res.setEDNS(0, ed_buff, 0, null); //EDNS0 support
    boolean save_abort = abort; 
    abort = true;
    if (register_test_result( 2, first_check( res, "org." , Type.DNSKEY, true), 
 			       msg = "org DNSKEY lookup failed RFC4034", 
 			       false)) {
	if (--fail_allowed < 0) 
	    return false;
    }
    abort = save_abort;
    
    // Check for new/unknown record (needs updating over time) 
    boolean fc = first_check( res, "tlsa.ogud.com", /* Type.TLSA */  52, true);
    if (register_test_result( 3, fc, msg = "Unknown RR failure RFC3597", 
 			      false) || fc == false) {
      if (--fail_allowed < 0) return false;
 	//	return grade;  // No abort here 
    } 

    // Is TCP supported 
    if (register_test_result(4, tcp_test(resolver), 
 			     msg = "TCP Failed RFC1035/RFC5966 violation", 
 			     false)) {
 	return true;
    }
    
    // is DNAME supported and returned 
    if (register_test_result(5, dname_check(res, "grade.goal.ogud.com.", 
					    Type.TXT, "grade.shinkuro.com.", 
					    false), 
 			     msg = "DNAME Not Supported RFC2672/RFC6672", 
 			     false))
 	return true; 

    

    // Make sure we got some answer that was bigger than 512 bytes i.e. via
    // Edns0 or TCP 
    if (register_test_result(6, big_ok, msg = "No answers > 512 seen", 
			     false))
 	return true;
    
    return dnssec_tests(res);
}


private static String 
addr_lookup(String resolver) {
    if (debug)
	print("addr_lookup: " + resolver);
    SimpleResolver mRes = get_resolver(resolver);
    if (mRes == null) { 
	String err = "addr_lookup() failed " + resolver;
	print(err);
	return "NoResolver";
    }
    
    Message msg = make_query(getting_address, Type.A, mRes);
    if (msg == null) {
        msg = make_query(getting_address, Type.A, mRes);
    }

    if (msg == null)
	return "NANA";
    Record Ans [] = msg.getSectionArray(Section.ANSWER); 
    if (Ans.length > 0) {
	int type = Ans[0].getType();
	if ( type == Type.TXT || type == Type.A || type == Type.AAAA) {
	    Record rr = Ans[0];
	    String out = rr.rdataToString();
	    if (out != null) {
	      if (type == Type.TXT)
		return out.substring(1,out.length()-1);
	      else
		return out; 
	    }
	    return "BAD";
	} else
	    return Type.string(Ans[0].getType()); 
    }
    return "EMPTY";
}    

public static String 
myaddr(String str) { 
    return addr_lookup(str); 
}

public static String 
myaddr() {
    return addr_lookup(submit);
} 

static String user_message = ".Msg=";
public static void 
set_message( String msg) { 
  /* The input string needs to be converted into DNS label  
     right now I only copy it to the output 
  */
  user_message = user_message + msg;
}


    /* generate_report will send a report back to central resolver */
private static String 
generate_report(String resolver) { 
    String out = "Generate_report:" + " " + resolver + " " + submit_report;
    String Resolv = "N/A";

    if (debug)
	print (out);

    String result = "Test=" + string_result();
    Resolv = myaddr(resolver); 
      // use this as an idicator if we can talk directly to resolver 
    String My_addr = myaddr(); // use dnsjava recursive resolver to get 
    // own address 
    
    String name = result + ".NS=" + resolver + 
      ".Resolv=" + Resolv + ".Me=" + My_addr + ".Version=" + get_version()
      + user_message;
	// submit directly to authoritave resolver
    if (submit_report) {
	Message msg = null;
	SimpleResolver rep = get_resolver( submit);
	if ((My_addr == null) || (My_addr.length() < 6))
	  rep = get_resolver(null);	  // go via recursive resolver

	if (rep != null) {

	    String qname = name  + "." + "report." + zone;
	    if (debug) {
		print ((String) "Making query " + qname);
	    }
	    msg = make_query(qname, Type.TXT, rep);
	    if (msg == null)
		print ("Report failed: " + qname);
	    else if (msg.getHeader().getCount(Section.ANSWER) < 1)
		print ("Submission error: " + msg);
	}
	if ((rep == null) || (msg == null)) {
	    print ("Reporting failed: " + name);
	    reports_failed += 1;
	    // how to store for future use ??? 
	} else if (show_report == true) {
	    print ("Reported result: " + "." + result + 
		   " Addr=" + resolver);
	}
    } else if (debug) {
	String output = "Result Not submitted: " + name;
	print(output);
    }
    return name;
}

public static String
evaluate_resolver( String resolver) {
    String out = "";
    String msg = "Resolver " + resolver;
    String results = "Not a resolver " + resolver;

    reason = "";
    report_reset();
	    
    if (debug)
	print( msg);

    boolean success= run_tests(resolver, 14 /* fix later */);
    if ((reason.length() > 0) && detailed_report )
	msg = msg + " --> " + reason;

    if (success == true) {
	generate_report(resolver);
	results = string_result();
    }
    if(debug) 
	print(results);
    return results;
}
}

