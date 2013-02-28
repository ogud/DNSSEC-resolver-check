
// Copyright (c) 2013 Shinkuro INC 
// Date: Feb 2013 
// 

/** @author Olafur Gudmundsson &lt;ogud@shinkuro.com&gt; */
/* Licence BSD */ 
/*
   This program reqires the DNSjava library tested with version 2.1.
*/
import java.io.*;
import java.net.*;
import org.xbill.DNS.*;

public class Squery { 
  boolean saw_timeout = false;
  String zone_name = "submit.dnssecready.net.";
  String getting_address = "whatsmyip." + zone_name;

  public  static void 
  print (Object o) {
    System.out.println(o); 
  }
  
  public boolean query_timeout() {
    return saw_timeout;
  }
  
    public void set_zone(String name) {
	zone_name = name; 
	getting_address =  "whatsmyip." + zone_name;
    }

    String zone() {
	return zone_name;
    }

  /* convert from Sting to Name (DNS format) 
   * hide exceptions (that should not happen)
   */
  public Name 
  Str_to_Name( String na) {
    Name my_name = null;
    try { 
 	my_name = Name.fromString(na, Name.root);
    } catch (Exception e) {
        print("Name error rrsig_check " + na);
 	my_name = null;
    }
    return my_name;
}

SimpleResolver
get_resolver( String resolver, boolean debug){
    SimpleResolver tcp; 
    try {
      if (resolver != null) 
	tcp = new SimpleResolver(resolver);
      else 
	tcp = new SimpleResolver();
    } catch (Exception e) {
      	print( "Can not create resolver ");
	if (debug) 
	    print( e.toString());
 	return null;
    }
    //    tcp.setEDNS(0, 4000, ExtendedFlags.DO, null);
    return tcp;
}

SimpleResolver 
get_resolver(String resolver) {
    return get_resolver(resolver, false);
}
     /* make_query() a simple query interface that catches exceptions 
      *      when there is an error it returns a null object 
      *      hides exceptions from main program 
      *  Arguments: domain: the domain name to look up
      *             type: the type of the record to lookup
      *             res: The resolver to use t
      */
Message 
make_query( String domain, int type, SimpleResolver res, boolean debug) {
    Message query, response = null;
    Name name;
    int dclass = DClass.IN;
    int response_size = 0;
    int rcode = 0;
    saw_timeout = false;
    if ((name = Str_to_Name(domain)) == null) 
 	return null;
    
    Record rec = Record.newRecord(name, type, dclass);
    try {
 	query = Message.newQuery(rec);
    } 
    catch (Exception e) {
        print( "Query Construction Error " + domain + " " + 
			    Type.string(type));
 	return null;
    }

    try { 
 	response = res.send(query);
    }
    catch (SocketTimeoutException t) {
      if (debug) {
	print ("catching Timeout exception");
      }
      saw_timeout = true;
      return null;
    }
    catch (Exception e) {
        print( "make query failed : " + response ); 
	if (debug) {
	  print ("catching socket exception: " + e);
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

Message 
make_query( String domain, int type, SimpleResolver res) {
  return make_query(domain, type, res, false);
}


String 
addr_lookup(String resolver, boolean debug) {
    if (debug)
	print("addr_lookup: " + resolver);
    SimpleResolver mRes = get_resolver(resolver, debug);
    if (mRes == null) { 
	String err = "addr_lookup() failed " + resolver;
	print(err);
	return "NoResolver";
    }
    
    Message msg = make_query(getting_address, Type.A, mRes, debug);
    if (msg == null) {
      msg = make_query(getting_address, Type.A, mRes, debug);
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

String 
addr_lookup(String resolver) {
    return addr_lookup(resolver, false);

}

}
