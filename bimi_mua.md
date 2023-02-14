%%%
Title = "BIMI on an Independent MUA"
abbrev = "BIMI-MUA"
category = "standard"
docName = "draft-brotman-bimi-mua-00"
ipr = "trust200902"
area = "Applications"
workgroup = ""
keyword = [""]

date = 2023-02-02T00:00:00Z

[seriesInfo]
name="RFC"
value="draft-brotman-bimi-mua-00"
stream="IETF"
status="standard"
   
[[author]]
initials="A."
surname="Brotman"
fullname="Alex Brotman"
organization="Comcast, Inc"
 [author.address]
 email="alex_brotman@comcast.com"
%%%

.# Abstract

This document describes a method by which a receiving MTA may insert Brand 
Indicators for Message Identification (BIMI) headers into a message in such 
a way that a third party MUA can not only use the information in those 
headers but also validate that the headers were inserted by the MTA. 

{mainmatter}

# Introduction

Brand Indicators for Message Identification (BIMI) describes a method to 
enable Domain Owners to coordinate with Mailbox Providers (MBPs), Mail 
Transfer Agents (MTAs), and Mail User Agents (MUAs) in the display of 
brand-specific Indicators (e.g., logos) next to properly authenticated 
messages.

BIMI relies on DMARC, which in turn relies on both SPF and DKIM validation 
for the message in question, and it is generally accepted that an MTA is best 
positioned to do the SPF and DKIM validation that underpin DMARC, since it 
has the cleanest access to the data necessary for such validation. An MUA 
almost certainly cannot perform SPF validation on a message, as it will not 
know the sending IP of the message, and an MUA could only perform DKIM 
validation on a message if the MTA has not altered the DKIM-protected parts of 
the message. This makes the simplest path to the display of a BIMI 
Indicator one where the MTA performs the required checks for DMARC and BIMI 
and records the results of those checks in a way that can be accessed by the 
MUA.

BIMI makes no requirement that the MTA handling a message and the MUA reading 
and displaying it be operated by the same entity. In cases where a mailbox 
holder uses their MBP's MUA to read the contents of their mailbox, it is a 
relatively simple matter for the MTA and MUA to interoperate in a way in 
which the display of the BIMI Indicator can be controlled by the MBP. 

What is less simple is the interoperability between an MBP's MTAs and message 
stores and a third-party MUA. In this scenario, there must exist a standard 
way for an MTA to communicate BIMI and DMARC validation results to the MUA in 
a way that can be verified by the MTA. In addition, the MBP through its 
message store must be able to indicate that a BIMI Indicator and/or its 
Evidence Document has been revoked if circumstances require.

This document describes a method for achieving interoperability between an 
MBP's MTAs and message stores and a third-party MUA.


# Validation Information

The receiving entity may add two headers, BIMI-Location and BIMI-Indicator.
These two headers are meant to aid the MUA with the location of the
BIMI-related information, as well as base64-encoded SVG image file.

Additionally, a receiver employing this method MUST add another header
to the message, BIMI-Receiver-Information. This will contain a
`date-time` (from [@!RFC5322]), and sha256-encoded hash from the
local part of the recipient, and then the `domain` (again from RFC5322)

BIMI-Receiver-Information: date: date-time ; rcpt: sha256-local @ domain

date-time: RFC5322

domain: RFC5322

sha256-local: 64( HEXDIG )

An example might be:

BIMI-Receiver-Information: date: Tue, 25 Oct 2022 01:05:55 +0000 ; \
  rcpt: 6d9010b2b7a1483b256ae7477738dba7c530bd9ba53db1d6691441e74b83608a@isp.net

# BIMI-Receiver-Signature

The MTA or other entity that performed the BIMI validation of the message 
MUST, if the message passed all BIMI validation checks, insert a 
BIMI-Receiver-Signature header constructed in a manner consistent with the 
creation of a DKIM-Signature header as defined in [RFC6376]. This header 
MUST include all the BIMI-Location, BIMI-Selector, and 
BIMI-Receiver-Information headers as headers that were signed by this 
signature. 

This signature will be validated by the MUA in the same manner that a 
DKIM-Signature header is validated, and successful validation of this header 
will indicate that the signing domain inserted the signed headers. 

The public key to support this signing activity will be published in the DNS 
at a location one or more levels below the name "_bimi.signingDomain". For 
example, an MBP named "isp.net" might publish its public key at 
"sel_sign._bimi.isp.net". For the purposes of this document, we will refer 
to "sel_sign" as the "True Selector".


The selector specified in the s= tag of this signature will be a 
pseudo-selector constructed by prepending the full domain from the 
RFC5322.From header to the "True Selector". In the INFORMATIVE EXAMPLE of a 
BIMI-Receiver-Signature header shown below, the s= tag is assigned the value 
"marketing.example.org.sel_sign", which means that the RFC5322.From header 
for the message contained the domain "marketing.example.org".  

BIMI-Receiver-Signature: v=BIMI1; d=isp.net; s=marketing.example.org.sel_sign; 
c=canonicalization; h=BIMI-Location:BIMI-Selector:BIMI-Receiver-Information;
b=<SIGNATURE_BLOB>; t=timestamp

## Public Key Publishing

While the above method describing "pseudo-selectors" might seem to require 
that isp.net publish an infinite number of DKIM public keys in order to 
support validation of its BIMI-Receiver-Signature headers, that is not the 
case. Instead, validation of these signature headers will rely on publishing 
a DNS wildcard record, while revocation of BIMI logos will rely on the 
publishing of empty records to match the domains for which the MBP no longer 
wishes to support validation of BIMI logos.

As mentioned in the previous section, the MBP will publish its public key 
for supporting validation of BIMI-Receiver-Signatures at the name 
matching this pattern:

<True Selector>._bimi.<signing Domain>

In the example above that would mean publishing a DKIM public key as follows:

sel_sign._bimi.isp.net TXT "v=BIMI1; p=<public_key_data>"

To support validation of its signatures where the selector is the 
"pseudo-selector" described in the previous section, the MBP will also 
publish the following DNS wildcard record:

*.sel_sign._bimi.isp.net CNAME sel_sign._bimi.isp.net.


# Revocation

There could exist any number of reasons for a receiving entity to no
longer desire to display iconography for a given sending domain. This could
include certificate revocation from the CA, diminished local reputation, 
extensive abuse reports, or anything else.

In the case where this happens, the MBP (again, isp.net) can publish a NULL
record at the location where the domain would normally match a wildcard. If
we also use `example.net`, this may look like this:

example.net.sel_sign._bimi.isp.net TXT "v=BIMI1;"

The important part is that the DNS response does not include a functional
public key that could be used to validate the signature.

This would ensure the MUA is no longer able to retrieve the public keys
necessary to validate the signature.  In this case, it should no longer 
utilize the headers, even though they do still exist in the stored message.


# Security Considerations

## Key Separation

The key used to sign these BIMI headers should not be shared with another
portion of the receiving platform.

## Header Removal

Any MBP receiving these headers intact should remove these and perform their
own evaluations.

# Appendix A

For purposes below, sending is `example.com`, MBP is `isp.net`, and selector
is `sel_sign`.

## Normal Operational Steps

* ESP sends message to MBP containing appropriate headers for BIMI usage
* MBP performs DKIM/SPF/DMARC steps
* Presuming prior step works properly, MBP evaluates BIMI
* Based on localised requirements, MBP adds headers to email
   * BIMI-Location
   * BIMI-Indicator
* MBP additionally adds header specified in this document
   * BIMI-Receiver-Information
       * Includes time of receipt, sha256 of local rcpt, and the "@isp.net" portion
* MBP signs all three headers using DKIM-style cryptography
   * Adds new header containing hash, as well as s/d attributes
* ...
* MBP stores message in platform
* MUA retrieves message via IMAP or POP3
* User opens message or MUA uses data during list view
* MUA inspects looking for BIMI data
* MUA sees signature
    * MUA verifies that the destination email address matches the signing domain
    * Looks for public keys at `example.com.sel_sign._bimi.isp.net`
* MUA validates signature
* MUA displays BIMI logo as needed (list or message view)

## Revoked Operational Steps

* ESP sends message to MBP containing appropriate headers for BIMI usage
* MBP performs DKIM/SPF/DMARC steps
* Presuming prior step works properly, MBP evaluates BIMI
* Based on localised requirements, MBP adds headers to email
   * BIMI-Location
   * BIMI-Indicator
* MBP additionally adds header specified in this document
   * BIMI-Receiver-Information
       * Includes time of receipt, sha256 of local rcpt, and the "@isp.net" portion
* MBP signs all three headers using DKIM-style cryptography
   * Adds new header containing hash, as well as s/d attributes
* ...
* MBP stores message in platform
* MUA retrieves message via IMAP or POP3
* User opens message or MUA uses data during list view
* MUA inspects looking for BIMI data
* MUA sees signature
    * MUA verifies that the destination email address matches the signing domain
    * Looks for public keys at `example.com.sel_sign._bimi.isp.net`
    * MUA sees a value of "v=BIMI1;" or something else
* MUA does NOT display logos for this message (the domain as a whole)

## Sample headers

BIMI-Receiver-Signature: s=example.com.sel_sign;d=isp.net;p=<signature_data>
BIMI-Receiver-Information: date: Tue, 25 Oct 2022 15:14:12 +00:00 ;
  rcpt=d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1@isp.net
BIMI-Location: v=BIMI1;a=https://bimi.example.com/bimi/evidence.pem;
  l=https://bimi.example.com/bimi/logo.svg
BIMI-Indicator: <base64_SVG_Data>
Authentication-Results: spf=pass marketing.example.com;
  dkim=pass (signature was verified) header.d=example.com; dmarc=pass
  header.from=example.com; bimi=pass header.d=example.com
  header.selector=our_selector
DKIM-Signature: d=example.com;s=d_s;h=BIMI-Selector:From:To:Date:Message-Id;
  bh=<hash_data>;b=<signature_data>
BIMI-Selector: v=BIMI1;s=our_selector

# Contributors

# Notes

# References

{backmatter}
