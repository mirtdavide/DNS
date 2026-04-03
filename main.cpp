#include "dns_handler.hpp"
#include "thread_pool.hpp"
#include "packet_data.hpp"
#include <unistd.h>   
#define SERVER_PORT 1053

int main(){
    /* Socket Creation using the socket function defined here https://man7.org/linux/man-pages/man2/socket.2.html
    domain = AF_INET -> IPV4, 
    type SOCK_DGRAM -> supports connectionless(such as UDP), 
    protocol = 0 -> Default protocol for the selected "type"
    If there are no problems it will return a positive integer
    */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    //We check for errors (if non positive) 
    if (sock < 0) {
        perror("Error occured while opening the socket"); //We output the error
        return 1;
    }
    //Specific structure sockadrr_in (in -> INET so it is IPV4)  contains: Family, IP Address, Port
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET; //We using IPV4
    servaddr.sin_addr.s_addr = INADDR_ANY; // Accepts packets from any interface (any network card we have)
    servaddr.sin_port = htons(SERVER_PORT);       // Listening Port (We convert this in Network Byte Order)

    /*bind function defined here https://man7.org/linux/man-pages/man2/bind.2.html
    Binds our socket to an address
    Wants:
    our socket file descriptor -> so our sock variable, 
    The afore defined structure as a sockaddr so we cast it, 
    The dimension of our sockaddr_in variable
    */
    //Again it returns a non positive integer if there are any errors so we check
    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        //We use the perror function to read the errno variable set by the failure of the bind function
        perror("Error occured while binding the socket to an address");//We output the error
        close(sock); //We close the socket
        return 1;
    }

    std::cout << "Server DNS IPV4 active on  port "<<SERVER_PORT<<std::endl;

    /*We create the buffer where we will receive packets
    uint8_t: 
    uint = Unsigned Integer -> Not considering the SIGN bit, i guess it could lead to disastrous things when we operate with the numbers
    8 = Occupies exactly 8 bits in memory so a Byte.
    512 Maximum dimension of a DNS Packet UDP, 512 Bytes as defined in the RFC 1053
    */
    uint8_t rec_buffer[512];
    
    //sockaddr Structure used to identify the client that sends us a package, atp not defined but will be filled by the recvfrom() function
    struct sockaddr_in cliaddr;
    
    //Infinite cycle waiting to receive something
    while(true){

        //Set the rec_buffer to 0 before working with it. clean slate
        std::memset(rec_buffer, 0, sizeof(rec_buffer)); 

        //The recvfrom we use in the next line will take this and will write on it the size of the address of the coming client
        socklen_t len = sizeof(cliaddr);
        /*recvfrom function defined here https://man7.org/linux/man-pages/man3/recvfrom.3p.html
        Receives messages from connection or connection-less sockets.
        Wants:
        our socket fd -> sock
        a buffer and its size -> our afore defined rec_buffer, the function will write here what it receives
        flags -> we set 0 , no special falgs active since we want the default behavior that being cyclical listening, storing of the message and erasure from the interface
        a sockaddr structure (we cast our cliaddr), the function will write some useful stuff such as the address of the client
        address_len -> since on the sockaddr we did not use a null pointer but a structure, we can use our len and give it as input; the function will write
        on it the size of the stored address.
        Returns the length of the received message stored in buffer
        If an error occurs it returns -1, it may return 0 for connection oriented protocols. We are using UDP so we care only about a non positive return
        */
        ssize_t n = recvfrom(sock, rec_buffer, sizeof(rec_buffer), 0, (struct sockaddr *)&cliaddr, &len);


        if(n < 0){
            perror("Error occured while receiving");
            continue;
        }
        process_dns_packet(rec_buffer, n, sock, cliaddr,len);





    }
}