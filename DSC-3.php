<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>DNSSEC Resolver Check (DRC)</title>
  <link type="text/css" href="http://code.jquery.com/ui/1.10.1/themes/redmond/jquery-ui.css" rel="stylesheet" />
  <script src="http://code.jquery.com/jquery-1.9.1.min.js"></script>
  <script src="http://code.jquery.com/ui/1.10.1/jquery-ui.js"></script>
  <script src="lc.min.js"></script>
 
<style type="text/css">
.small-text {
    font-size: 55%;
}
.italic {
    font-style:italic;
}
.working {
    color: MediumVioletRed;
}
.list-start {
    margin-top: 10px;
    margin-left: 25px;
}
.list-entry-begin {
    margin-top: 10px;
    width: 850px;
}
.list-entry-left {
    display: inline-block;
    text-align: left;
    width: 30%;
}
.list-entry-middle {
    display: inline-block;
    text-align: left;
    width: 40%;
}
.list-entry-right {
    display: inline-block;
    text-align: left;
    width: 23%;
    font-family: "Courier New", "Lucinda Console", Monospace;
}
.list-entry-delete-button {
    display: inline-block;
    width: 2%;
}
.monospace-font {
    font-family: "Courier New", "Lucinda Console", Monospace;
}
.ui-tooltip {
    font-size: 10pt;
    font-family:Calibri;
}
</style>
</head>

<script type="text/javascript">

    var item_index = 0;

    $(document).ready(function() {
        
        // add tooltips to the document (anything with class list-entry-middle)
        $( document ).tooltip({content: supplyTooltipContent,
                               items: ".list-entry-middle a",
                               show: { effect: "blind", duration: 800 },
                               hide: { effect: "blind", duration: 500 }});

        // attach a listCtl to the UserResultsList
        $('#UserResultsList').listCtl({inhibitClick: false});
        
        // attach a keyup handler to the text input
        $('#ip_addr_in').keyup(testCheckResolver);

        // give the UI some time to show up...
        setTimeout(readyPart2, 100);
    });
    
    function readyPart2() {

        // put up the version info
        var version = dsc_app.getAppletInfo();
        var version_pieces = version.split("\n");
        var innerHTML = "";
        for (i=0; i<version_pieces.length; i++) {
            piece = version_pieces[i];
            innerHTML += piece + "<br>";
        }
        VersionTxt.innerHTML = innerHTML;

        // get the local resolvers
        var localResolverAddressesString = dsc_app.getLocalResolverAddresses();
        
        // clear the "working..." text 
        var theLocalResultsList = $('#LocalResultsList');
        theLocalResultsList.removeClass('working');
        theLocalResultsList.text("");
        
        // create the local resolvers list control
        theLocalResultsList.listCtl({inhibitClick: false});

        // and load it
        var resolverAddresses = localResolverAddressesString.split(",");
        for (i=0; i<resolverAddresses.length; i++) {
            
            var resolverAddress = resolverAddresses[i];
            checkResolver(theLocalResultsList, resolverAddress, false);
        }
    }

    function supplyTooltipContent(htmlCB) {
        
        var compoundUrl = this.href;
        if (compoundUrl != null) {
            var pieces = compoundUrl.split("?");
            
            $.get(pieces[0], pieces[1], function(data, status) {
                htmlCB(data);
            }, "html");
        }
    }
    
    function testCheckResolver(eventObject) {

        // if the user hit enter, then check the resolver
        if (eventObject.which == 13) {

            var userResultsList = $('#UserResultsList');
            var resolverAddress = eventObject.currentTarget.value;

            checkResolver(userResultsList, resolverAddress, true);
        
            // select the input text so the user can go again
            ip_addr_in.select();
        }
    }
    
    function checkResolver(resultsList, resolverAddress, allowDelete) {

        var html = format_list_entry(resolverAddress, null);

        resultsList.listCtl("addItem", html);
        var index = resultsList.listCtl("itemCount") - 1;
        var item = resultsList.listCtl("getItemByIndex", index);
        item.addClass('working');
        
        if (false) {
            // /////////////////////////////////////////////
            // permissions issue - this method doesn't work.
            // //////////////////////////////////////////////
            
            // start the checker on the address
            dsc_app.startResolverChecker(resolverAddress);

            // try getting results every 1/10 of a second...
            var intId = setInterval(tryGetResults, 100);
        
            function tryGetResults() {
                        
                var resolverBehavior = dsc_app.getResolverCheckerResult();
                if (resolverBehavior == null) {
                    return;
                }
                clearInterval(intId);

                putResults(resultsList, resolverAddress, resolverBehavior, index, allowDelete);            
            }
            
        } else {
            // blocking but works...
            var resolverBehavior = dsc_app.doResolverCheck(resolverAddress);
            putResults(resultsList, resolverAddress, resolverBehavior, index, allowDelete);
        }
    }

    function putResults(resultsList, resolverAddress, resolverBehavior, index, allowDelete) {
    
        // format the behavior result and display it
        var html = format_list_entry(resolverAddress, resolverBehavior); 
        resultsList.listCtl("deleteItem", index);
        resultsList.listCtl("addItem", html, index);
        var item = resultsList.listCtl("getItemByIndex", index);

        // add a delete icon if indicated
        if (allowDelete) {
           item.find('.list-entry-delete-button').button({
                icons: {
                    primary: "ui-icon-trash"
                },
                text: false
            }).click(delete_entry);
        }
    }
    
    function format_list_entry(resolverAddress, resolverBehavior) {
        
        var pfax = "";
        var behavior = "working...";
        if (resolverBehavior != null) {
            var inxOfFirstComma = resolverBehavior.indexOf(",");
            if (inxOfFirstComma >= 0) {
                pfax = resolverBehavior.slice(0, inxOfFirstComma);
                behavior = resolverBehavior.slice(inxOfFirstComma+1);
            } else {
                behavior = resolverBehavior;
            }
        }
        
        var inxOfREquals = pfax.indexOf("R=");
        if (inxOfREquals >= 0) {
            behavior = pfax.slice(inxOfREquals+2);
        }
        
        item_index += 1;
        var htmlStr = "<div class='list-entry-begin' id='user-results-list-item-" + item_index + "'>" 
                    + "<span class='list-entry-left'>" + resolverAddress + "</span>" 
                    + "<span class='list-entry-middle'><a href='DNSSEC_Check_Help.php?behavior=" 
                          + encodeURIComponent(behavior) 
                          + "' target='drc_help'>" 
                          + behavior + "</a></span>" 
                    + "<span class='list-entry-right'>" + pfax + "</span>"
                    + "<span class='list-entry-delete-button' title='Delete me'/>";
        htmlStr += "</div>";
        return htmlStr;
    }
    
    /*
     * not general - only deletes items in the UserResultsList
     */
    function delete_entry(eventData) {
        $('#UserResultsList').listCtl("deleteItemByAttr", 'id', eventData.currentTarget.parentElement.id);
    }
</script>

<body>
<h1 align='center'>DNSSEC Resolver Check</h1>

<p>The local DNS Resolvers available at your browser's IP Address are listed below along with the results of the 
DNSSEC Resolver Check:

<div id="LocalResultsList" class="list-start working">working...</div>

<p>You can also enter a Resolver name or address that you would like to run DRC on.  Type it in the input box below and
hit enter, and the  results will show up below that.

<p>
<label for="ip_addr_in">Resolver to check: </label>
<input id="ip_addr_in" type="text" autofocus width="100" title="Enter the address of a resolver to check"/>

<div id="UserResultsList" class="list-start"></div>

<p>DNSSEC Resolver Check (DRC) evaluates DNS resolvers. The evaluation tells you about the DNSSEC capabilities of your local 
resolvers and any additional resolvers you may wish to check.  When DRC starts, it evaluates the locally configured resolvers.  
After that you can check additional resolvers by typing their name or address in the text box provided and hitting carriage return.

<p>DRC presents the results of checking a resolver as shown below:

<p>
<center>
<div class='list-entry-begin' >
    <span class='list-entry-left italic'>address</span>
    <span class='list-entry-middle italic'>behavior</span>
    <span class='list-entry-right italic'>test results</span>
</div>
</center>

<p>The first string repeats the address or name of the resolver.  
The next string provides a description of the capability level of the 
resolver and within parenthesis, shows any capabilities that the resolver is missing for 
a full standing.  When the applet has presented a result, you may hover over the text 
to get some help text that describes this capability level.

<p>This textual description of the results is followed by a string such as <b class="monospace-font">PPPPFPAAFAAAP</b>.  
Each letter in <b class="monospace-font">PPPPFPAAFAAAP</b> is the symbolic result of one of 13 tests that the Applet runs on the 
resolver. From left to right these letters represent T1 through T13. 
You can  <a id="drc_test_help" href="DNSSEC_Check_Test_Help.html" target="drc_test_help" title="Description of the tests.">click here</a> 
for a description of each of these tests.  



<p><div id="VersionTxt" class="small-text"></div>


<?	
		$useApplet=0;
		$user_agent = $_SERVER['HTTP_USER_AGENT'];
	   
		if(stristr($user_agent,"konqueror") || stristr($user_agent,"macintosh") || stristr($user_agent,"opera"))
		{ 		
			$useApplet=1;
			echo '<applet name="dscheck"
					archive="DNSSEC_Check-1.0.2.jar"
					code="DNSSEC_Check"
					width="1" MAYSCRIPT name="dsc_app" id="dsc_app"
					height="1">';			
		}
		else
		{			   
			if(strstr($user_agent,"MSIE")) { 
				echo '<object classid="clsid:8AD9C840-044E-11D1-B3E9-00805F499D93"
					width= "1" height= "1" style="border-width:0;"  id="dsc_app" name="dsc_app"
					codebase="http://java.sun.com/products/plugin/autodl/jinstall-1_4_1-windows-i586.cab#version=1,4,1" name="jsap" id="jsap">';
			} else {
				echo '<object type="application/x-java-applet;version=1.4.1"
					width= "1" height= "1"  name="dsc_app" id="dsc_app">';
			} 
			echo '	<param name="archive" value="DNSSEC_Check-1.0.2.jar">
                    <param name="code" value="DNSSEC_Check">
                    <param name="mayscript" value="yes">
                    <param name="scriptable" value="true">
                    <param name="name" value="dsapplet">';
		}
		if($useApplet==1)
		{
			echo '</applet>';
		}
		else
		{
			echo '</object>';
		}
?>

</body>

</html>
