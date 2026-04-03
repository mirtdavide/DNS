#ifndef DNS_HANDLER_HPP
#define DNS_HANDLER_HPP

#include <netinet/in.h>  // To use structures such as sockaddr_in
#include <unistd.h>      // To use ssize_t and close()?
#include <cstdint>       // To use uint8_t
#include "dns_protocol.hpp"
#include "packet_data.hpp"
#include <iostream>
#include <cstring>
#include <sys/socket.h> // Sockets
#include <arpa/inet.h>  // Endianess functions

/*
Builds and sends a DNS response back to the client.
Takes the socket, the client address and the buffer with the parsed query.
*/
void send_dns_response(int sock, struct sockaddr_in& cliaddr, socklen_t clilen, uint8_t* buffer, uint8_t* query_end);

/*
Processes a received DNS packet.
Parses the header and QNAME, then calls send_dns_response().
*/
void process_dns_packet(uint8_t* buffer, ssize_t n, int sock, struct sockaddr_in& cliaddr, socklen_t clilen);

#endif