%%%
Title = "BIMI on an Independent MUA"
abbrev = "BIMI-MUA"
category = "standard"
docName = "draft-brotman-bimi-mua-00"
ipr = "trust200902"
area = "Applications"
workgroup = ""
keyword = [""]

date = 2022-10-25T00:00:00Z

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


A method by which the receiving MTA may pass some information to the
user MUA, and validate that information was added by the receiving
system.


{mainmatter}

# Introduction

   Branded Indicators for Message Identifcation (BIMI) is meant to work
   in a situation where the MUA is independent of the receiving entity,
   otherwise known as a third-party email client.  When doing so, it is
   important that the MUA is able to validate any information provided
   to it by the receiver (or MBP).

   As noted in the primary BIMI document, the MBP may add two headers,
   BIMI-Location and BIMI-Indicator.  It is understood that a BIMI-aware
   receiver will remove these headers if they exist upon message
   arrival.  However, an independent MUA may need some additional
   assurances that these headers were added by the entity responsible
   for their mailbox storage.

   Below is a method to cryptographically sign these data points, as
   well as some other identifying information.

# Validation Information

The receiving entity may add two headers, BIMI-Location and BIMI-Indicator.
These two headers are meant to aid the MUA with the location of the
BIMI-related information, as well as base64-encoded SVG image file.

Additionally, a receiver employing this method MUST add another header
to the message, BIMI-Receiver-Information. This will contain a
`date-time` (from [@!RFC5322]), and sha256-encoded hash from the
loal part of the recipient, and then the `domain` (again from RFC5322)

BIMI-Receiver-Information: date: date-time ; rcpt: sha256-local @ domain

date-time: RFC5322

domain: RFC5322

sha256-local: 64( HEXDIG )

An example might be:

BIMI-Receiver-Information: date: Tue, 25 Oct 2022 01:05:55 +0000 ; \
  rcpt: 6d9010b2b7a1483b256ae7477738dba7c530bd9ba53db1d6691441e74b83608a@isp.net

# Signature

To provide a higher level of assurance, the MBP should also now sign these 
three headers.  The system should use a DKIM-based [@!RFC6376] method as a 
system might also use when signing outbound messages.

The selector stated in the header is formed by joining the selector used 
during signing, along with prefixing the sending domain.

BIMI-Receiver-Signature: s=marketing.example.org.asdf1234;d=isp.net;p=<SIGNATURE_BLOB>

## Public Key Publishing

In order to avoid pubishing thousands of DKIM keys, the receiver should add 
the DKIM public key record as a TXT record, and then create a default 
sub-record response as a wildcard response to match that same TXT record.

In the case where the sending domain is "example.net", the receiving domain 
is "isp.net", and the selector is "sel_sign", the records would appear as 
below:

sel_sign._bimi.isp.net TXT "v=BIMI1;p=<public_key_data>"

Though, in order to complete the query for the method defined, there
must be a wildcard match:

*.sel_sign._bimi.isp.net CNAME sel_sign._bimi.isp.net

As noted above, this would allow the prefixed domain to continue to match
when queried from the MUA.  And so a query against 
"example.net.sel_sign._bimi.isp.net" would return the DKIM keys needed to
validate the signature added by the receiving system.

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
* Presuming prior step works properly, MBP evalutes BIMI
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
* Presuming prior step works properly, MBP evalutes BIMI
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
