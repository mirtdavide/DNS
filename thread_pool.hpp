#ifndef THREAD_POOL_HPP
#define THREAD_POOL_HPP

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <functional>
#include "dns_protocol.hpp"




class ThreadPool{
    private:

        std::vector<std::thread>    workers_;   //vector of threads NOTE: gotta settle with the number of threads
        std::queue<PacketData>      packet_q_;     //the queue where packets are waiting to be processed
        std::mutex                  mtx_;     //we use this to protect the queue
        std::condition_variable     cv_;        //workers sleep on this
        bool                        stop_;      //variable used to shut down a thread, is set in constructor
        
        /*
        Thread loop: waits for a packet, process it, then goes standby
        */
        void worker_loop();

    public:

        /*
        Constructor: spawns n threads based on the return of 
        hardware_concurrency(): as the default it returns the
        number of logical CPU cores available on the machine.
        NOTE: In future updates will change maybe
        */
        ThreadPool(int num_threads = std::thread::hardware_concurrency()); 

        ~ThreadPool(); //Destructor

         /*Called by main thread after we receive a packet, 
         pushes a copy of the received packet into the queue
         */
        void push(const PacketData& packet);
    



};

#endif