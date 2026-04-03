
#include "dns_handler.hpp"
#include "dns_protocol.hpp"


/*
After parsing the question we need to build an answer to send.
The response we send will be a DNS packet, so we need to have an Header, a Question and this time an Answer.
Header -> we need most of it we just modify some values: ID stays the same as it is a response to the Question, 
we change the QR Flag, the AA Flag, the ANCOUNT the NSCOUNT and the ARCOUNT .
Question-> we do not touch it, it stays the same.
Answer -> 
*/
void send_dns_response(int sock, struct sockaddr_in& cliaddr, socklen_t clilen, uint8_t* buffer, uint8_t* query_end) {
    //1.Building the header

    //We get the original header from the buffer as we need most of it.
    DNSHeader* header = reinterpret_cast<DNSHeader*>(buffer);

    
    // Sets the 15th bit(QR, Query Response, we set it to 1, this is a response) and 10th bit (AA, Authoritative Answer we set it to 1, we are the Authoritative for the asked domain)
    header->flags = 0x8400;

    header->ancount = 1; //ANCOUNT, answer count, we set it to 1 -> our answer.
    header->nscount = 0; //atm no additional authoritative servers
    header->arcount = 0; //atm no additional info

    //Bring it to internettian
    header->to_network_order();
    
    size_t current_offset = query_end - buffer;
    size_t expected_answer_size = 2 + sizeof(DNSResourceRecord) + 4; // Name pointer + RR + IP

    if (current_offset + expected_answer_size > 512) {
        std::cerr << "Error: Response would exceed 512 bytes. Truncation needed." << std::endl;
        // Qui in futuro potresti settare il bit TC (Truncated) nell'header
        return;
    }


    //2. As we do not touch the Question section we start building the Answer 
    //In the function parameters we passed a pointer to where the Question Section ends in the buffer
    uint8_t* answer_ptr = query_end;

    /*
    Stick with me cause this is wild. Apparently the DNS protocol uses a very weird commpression scheme in order to save length
    https://datatracker.ietf.org/doc/html/rfc1035 Section 4.1.4
    In this case a DNS Client that will read the next bytes will automatically know what to do.
    What we are doing is setting the name_ptr variable with the value of 0xc00c, this number in binary is
    1100 0000 0000 1100 
      c    0    0    c
    What we are interested in are the first 2 bits and the next 14
    The first 2 bits tell the client that what they are reading is a pointer (ofc there are other combinations but we are using the pointer one)
    The next 14 bits define the offset of this pointer
    So here we have a Pointer: (11 First 2 bits) that  is offset by 12 Positions
    This points exactly after the header where the NAME in the question is originally stored
    Pretty neat.
    */
    uint16_t name_ptr = htons(0xc00c);


    //Now we copy this to the buffer
    std::memcpy(answer_ptr, &name_ptr, sizeof(name_ptr)); //2 Bytes since it is the size of our name_ptr
    answer_ptr += 2; //Jump 2 bytes to write the next info

    //Declare the RR structure and set the fixed dimension fields of the Answer
    DNSResourceRecord rr;
    rr.type = 1;      // Type A -> IPV4 since this is an IPV4 server
    rr.qclass = 1;    // Class IN -> Internet
    rr.ttl = 300;     // TTL -> 300 seconds
    rr.rdlength = 4;  // Length of the answer, 4 bytes, one byte for each number of the IPV4 address we send
    rr.to_network_order(); //Convert these to internettian
    
    //Write them
    std::memcpy(answer_ptr, &rr, sizeof(DNSResourceRecord));
    answer_ptr += sizeof(DNSResourceRecord);

    //The ip we want to give back (ex: 93.184.216.34)
    uint8_t ip[4] = {93, 184, 216, 34}; 
    std::memcpy(answer_ptr, ip, 4);
    answer_ptr += 4; //Skip the 4 bytes so we reach the final position of our answer field

    // 3. Calculate the total dimension of the response and we send 
    size_t response_len = answer_ptr - buffer;
    sendto(sock, buffer, response_len, 0, (struct sockaddr*)&cliaddr, clilen);
    
    std::cout << "Sent Response: IP 93.184.216.34 back to client." << std::endl;
}





/*
Function to process a received message
it takes as input the buffer where the message is stored and the n size of the message to verify, the rest of the parameters will
be passed to the send_dns_response function when we call it as we end the processing
*/
void process_dns_packet(uint8_t* buffer, ssize_t n, int sock, struct sockaddr_in& cliaddr, socklen_t clilen) {
    //1. Header mapping
    
    /*We map the received bytes in the buffer to our defined header so we can extract data in an easier way, 
    the size is of course the header's. 
    We pray that whatever header is in buffer is exactly 12 bytes cause if it's not then we are in trouble.
    */
   
    DNSHeader* header = reinterpret_cast<DNSHeader*>(buffer);
    header->to_host_order();

    //Check if the QR Flag is set to 0, as we only process requests
    bool is_query = !(header->flags & 0x8000);   //Mask on the first bit of the flags field, the QR. If 0 it is a query, 1 it is a response. 
    if (!is_query) {
        //If QR = 1 it is an answer and we need to ignore it.
        return; 
    }

    

    /*Are we receiving a message with at least 12 Bytes? (DNS Header size) 
    Also we do some buffer overflow protection for memcpy used after. source: https://sternumiot.com/iot-blog/memcpy-c-function-examples-and-best-practices/
    */
    if (n < (ssize_t)sizeof(DNSHeader)) {
        std::cerr << "Message ignored: too small (" << n << " byte)." << std::endl;
        return;
    }

    std::cout << "Received " << n << " bytes from a client!" << std::endl;

  
    
    //2. QNAME Parsing
    /*Now we need to parse the buffer after the header in order to recompose the QNAME section
    We pray that whoever the hell is sending the bytes for the QNAME does it actually as defined in the RFC 1035 Section 3.1 so like this: 
    the first byte tells us the lenght of what are we going to read until the next "." character
    so as in google.com the first byte we read should be 6 (length of google) and then the bytes for the google characters
    We end reading when we encounter the null termination character
    */
    //We create a pointer that starts after 12 bytes of the buffer memory zone, of course it is a pointer that points to a byte
    uint8_t* reader = buffer + sizeof(DNSHeader);

    //Create a pointer that points at the end of the received message
    uint8_t* end_of_buffer = buffer + n;

    //Here inside we write our domain
    std::string domain_name = "";

    //This condition checks if we either are not out of bounds or if the byte we process inside reader is greater than 0 (The termination byte)
    while (reader < end_of_buffer && *reader > 0) {
        uint8_t label_len = *reader;
        
        //Check if we go out of bounds, specifically the number of letters + the byte of the label
        if (reader + label_len + 1 > end_of_buffer) {
            std::cerr << "Malformed QNAME (out of bounds)" << std::endl;
            return;
        }

        
        reader++; //Move away from the label byte.

       //Read for the label_len
        for (uint8_t i = 0; i < label_len; i++) {
            domain_name += static_cast<char>(*reader);
            reader++; // Advance the pointer for each letter parsed
        }

        //After we read the label_len bytes if we are not reading a 0 then it is a point
        if (reader < end_of_buffer && *reader > 0) {
            domain_name += ".";
        }
    }
    //Theoretically now the reader is on the 0 byte so we jump again to extract the next info.
    reader++;
    DNSFooter footer;

    //Check again if we do not get out of bounds
    if (reader + sizeof(DNSFooter) <= end_of_buffer) {
        std::memcpy(&footer, reader, sizeof(DNSFooter));
        footer.to_host_order();
        
    }
    reader += 4;
    
    
    //Print some info
    std::cout << "New DNS Message!" << std::endl;
    std::cout << "ID: " << header->id << std::endl;
    std::cout << "QDCount: " << header->qdcount << std::endl;
    std::cout << "ARCount: " << header->arcount << std::endl;
    std::cout << "QType: " << footer.qtype << std::endl;
    std::cout << "QClass: " << footer.qclass << std::endl;
    std::cout << "Type: " << (is_query ? "Query" : "Response") << std::endl;
    std::cout << "Domain requested: " << domain_name << std::endl;
    std::cout << "---------------------------" << std::endl;
    send_dns_response(sock, cliaddr, clilen, buffer, reader);
}