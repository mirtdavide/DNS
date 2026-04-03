#ifndef DNS_PROTOCOL_HPP
#define DNS_PROTOCOL_HPP

#include <cstdint>
#include <arpa/inet.h> 
/*For ntohs: Network to Host 
changes the format from Big Endian (Used in Internet)
to Little Endian used by hosts (used in memory)
Example: address 0x1234 on Internet would be written 12 and 34 Most significant to less significant
In memory it would be written 34 12 reversed 
*/
#include "packet_data.hpp"

// DNS Header Definition - Reference: RFC 1035 Section 4.1.1
// Link: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1

/*

Header:
ID: 16 Bit assigned by the program that generates any kind of query
QR: 1 Bit, 0 or 1, indicates if the message is a query (0) or a response (1)
OPCODE: 4 Bit, Specifies the kind of Query in the message
    0: standard query QUERY
    1: inverse query IQUERY
    2: server status request STATUS
    3 - 15: reserved for future use (???)
AA: 1 bit Authoritative Answer, this bit is valid in responses and 
    specifies that the server responding to the query is in fact the authority for the requested domain name
TC: 1 bit if set indicates that the message was truncated into multiple parts due to a size exceeding 
    the communication channel bandwidth, for udp usually 512 bytes
RD: 1 bit Recursion desired, this bit can be set in a query and then copied into the response
    if this bit is set it practically asks the server if it supports recursion to go and ask 
    other servers for the answer if it does not have it
RA: 1 bit Recursion Available, usually set in the response, indicates if Recursion is available or not
Z: 3 bit, Reserved for future use, must be 0, if not 0 it could be a malformed packet
RCODE: Response Code 4 Bit
    0: No Errors
    1: Format error, the server did not understand the query, malformed packet etc
    2: Server Failure, Internal problem in the name server, failed to respond to the query
    3: Name Error: Set in responses from Authoritative Servers, indicates that the domain name specified in the query does not exist
    4: Not Implemented: The nameserver does not support that kind of request
    5: Refused the nameserver refuses to respond to the query for policy reasons
    6-15: Reserved for future use
QDCOUNT: 16 bit How many questions are there (number of entries in the question section), usually 1
ANCOUNT: 16 Bit How many answers are there (number of entries in the answer section), usually 1, 0 in queries
NSCOUNT: 16 Bit Indicates the number of records in a name server in the authority records section
ARCOUNT: 16 Bit Indicates the number of records in a name server in the additional authority records section

*/

//We define the header structure
//Best practices tell us to put the fields of a struct in order of size, here they are all uint16
struct DNSHeader {
    uint16_t id;      // Identifier 16 Bit
    uint16_t flags;   // Flags Total 16 bit : QR, Opcode, AA, TC, RD, RA, Z, RCODE
    uint16_t qdcount; // Question Count: how many questions are there
    uint16_t ancount; // Answer Count: how many answers (0 in queries)
    uint16_t nscount; // Authority Record Count
    uint16_t arcount; // Additional Record Count

    /* We create a function where we use ntohs to convert the bytes from the format used on Internet (Big Endian) 
     to the memory format (Little Endian) */
    void to_host_order() {
        id = ntohs(id);
        flags = ntohs(flags);
        qdcount = ntohs(qdcount);
        ancount = ntohs(ancount);
        nscount = ntohs(nscount);
        arcount = ntohs(arcount);
    }
    void to_network_order() {
        id = htons(id);
        flags = htons(flags);
        qdcount = htons(qdcount);
        ancount = htons(ancount);
        nscount = htons(nscount);
        arcount = htons(arcount);
    }
    
}__attribute__((packed)); //Just to make sure

/*
Question:
QNAME: Variable length, so we are not making a struct in here, it is sequence of: a byte that tells us the lenght of what are we going to read and n bytes
it ends with a 0 byte that is basically the null label of the root.

QTYPE: this is of fixed size, 2 bytes (16bit). it is a code, specifies the type of the query.
    1: A (Host Address, IPv4)
    2: NS (Authoritative Name Server)
    5: CNAME (Canonical Name for an alias)
    15: MX (Mail Exchange)
    28: AAAA (IPv6 Address)
    255: * (A request for all records)

QCLASS: 16 Bit, specifies the class of the query.
    1: IN (Internet)
    3: CH (Chaos)
    255: * (Any class)
*/
struct DNSFooter {
    uint16_t qtype;  // Type of record (A, AAAA, MX, etc.)
    uint16_t qclass; // Class of query (usually 1 for Internet)

    //Get the values to host order so we can parse them
    void to_host_order() {
        qtype = ntohs(qtype);
        qclass = ntohs(qclass);
    }
}__attribute__((packed)); //Just to make sure

/*
Answer Section (Resource Record - RR):
NAME: Variable length, the domain name to which this resource record pertains.
Uses "Pointer Compression" (0xC00c) to point back to the QNAME in the question
section to save space and avoid redundancy.
TYPE: 16 Bit, specifies the type of data in the RDATA field (same as QTYPE values).
CLASS: 16 Bit, specifies the class of the data in the RDATA field (same as QCLASS values).
TTL: 32 Bit unsigned integer, Time To Live. Specifies the time interval (in seconds)
that the resource record may be cached before it should be discarded.
RDLENGTH: 16 Bit, specifies the length in octets of the RDATA field.
For a Type A record (IPv4), this value is always 4.
RDATA: Variable length, the actual data of the response.
In an 'A' record, it contains the 4 bytes representing the 32-bit IPv4 address.

*/
struct DNSResourceRecord {
    uint16_t type;
    uint16_t qclass; 
    uint32_t ttl;
    uint16_t rdlength;


    //We convert to network order before we send the respons
    void to_network_order() {
        type = htons(type);
        qclass = htons(qclass);
        ttl = htonl(ttl);
        rdlength = htons(rdlength);
    }

}__attribute__((packed)); //Just to make sure



#endif