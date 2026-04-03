#ifndef PACKET_DATA_HPP
#define PACKET_DATA_HPP
#include <iostream>
#include <arpa/inet.h> 

/*
This struct will contain a copy of the whole thing we receive from recvfrom. 
We pass this to a worker thread that will handle it.
Copying everytime should not influence the overall performance too much as this
is theoretically just 512 Bytes, but will check in future with some tests
*/
struct PacketData {
    uint8_t        buffer[512];
    ssize_t        len;
    sockaddr_in    cliaddr;
    socklen_t      clilen;
    int            sock; 
}__attribute__((packed)); //Just to make sure;


#endif