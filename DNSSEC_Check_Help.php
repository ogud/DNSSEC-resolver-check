<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>

<head>
<title>DNSSEC Resolver Check 3 Behavior</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>

<body>
<h2 align='center'>
<?php
$behavior = $_GET['behavior'];
echo $behavior;
?>
</h2>

<? 
if (strstr($behavior, "(")) {
    $behavior_pieces = explode("(", $behavior);
    $major_behavior = $behavior_pieces[0];
    $trimmed_modifier_set = substr($behavior_pieces[1], 0, -1);
    $modifiers = explode(",", $trimmed_modifier_set);
    if (!$modifiers) {
        $modifiers = array($trimmed_modifier_set);
    }
} else {
    $major_behavior = $behavior;
    $modifiers = array();
}
?>
<p>
<?
switch ($major_behavior)
{
case "Not a Resolver":
    echo "This is not a DNS resolver.";
    break;
case "TIMEOUT":
    echo "This host timed out when queried with a DNS question.";
    break;
case "Not DNSSEC":
    echo "This is a DNS resolver, but is not DNSSEC aware and does not support validation by its clients.";
    break;
case "Validator":
    echo "This DNS resolver is fully DNSSEC capable and can validate its DNS answers.";
    break;
case "Partial Validator":
    echo "This DNS resolver is partially DNSSEC capable. It can validate its DNS answers but does not implement all DNSSEC features.  Additional details follow.";
    break;
case "DNSSEC Aware":
    echo "This DNS resolver is capable of supplying answers containing DNSSEC information to a client. The client can do DNSSEC validation, but the resolver itself does not.";
    break;
case "Partial DNSSEC Aware":
    echo "This DNS resolver is partially capable of supplying answers containing DNSSEC information to a client. " .
         "The client can do DNSSEC validation, but the resolver itself does not. Additional details follow.";
    break;
case "REFUSED":
    echo "This DNS resolver refuses to supply an answer to our queries.";
    break;
default:
    echo "Unknown Behavior...";
    break;
}
?>

<?
foreach ($modifiers as $modifier) {
?>
<p>
<?
    switch ($modifier)
    {
    case "DNAME":
        echo "This resolver does not support DNAME (it failed T5).  DNAMES are important and, for certain zones, essential, but their use is still somewhat limited." .
             "We expect that implementations that do not yet support DNAME will do so relatively soon.";
        break;
    case "Unknown":
        echo "This resolver does not support Unknown record types (it failed T3).";
        break;
    case "NSEC3":
        echo "This resolver does not pass NSEC3 (it failed T11).  While NSEC3 is crucial and is used by .org, .gov and .com, it was not part of the original DNSSEC specification " .
             "and some otherwise compliant DNSSEC implementations don not recognize NSEC3 records.  We expect that this limitation will be resolved relatively quickly.";
        break;
    case "TCP":
        echo "This resolver does not support the transfer of large DNS responses over TCP (it failed T4). " . 
             "However this resolver does support large UDP records (it passed T12), which is essentially equivalent. " .
             "Some resolvers are purposefully configured not to accept queries over TCP.";
        break;
    case "SlowBig":
        echo "This resolver does not support the transfer of large DNS records via UDP (it failed T12), but does support the use of TCP (it passed T4), which is slower but essentially equivalent. " .
             "A resolver may behave this way because it is not configured to support large answers, or because the path between the querying system and the resolver cannot pass packets " .
             "that large or the receiving system does not support UDP packet re-assembly." ;
        break;
    case "NoBig":
        echo "This resolver cannot handle large responses whether via large UDP packets or TCP fallback (it failed both T4 and T12).";
        break;
    case "Permissive":
        echo "This resolver is Permissive - it returns unsigned answers.  Unsigned answers cannot be validated.";
        break;
    default:
        echo "This resolver returned an Unknown Modifier (" . $modifier . ")";
        break;
    }
}
?>

</body>
</html>