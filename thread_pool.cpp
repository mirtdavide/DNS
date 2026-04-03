#include "thread_pool.hpp"
#include "dns_protocol.hpp"
#include <iostream>


ThreadPool::ThreadPool(int num_threads){

    stop_ = false;
    for(int i = 0; i < num_threads; i++){
        //Create a thread that does the worker_loop function
        std::thread t(&ThreadPool::worker_loop,this);

        //Move said thread in a vector, TODO: try with only t to see what happens
        workers_.push_back(std::move(t));


    }


}


void ThreadPool::worker_loop(){
    while(true){

        //Get the lock on the mutex, it is now our turn
        std::unique_lock<std::mutex> lock(mtx_);
        
        //While the q is empty or the stop condition is set the thread releases the lock and waits to be called with notify_one
        while(packet_q_.empty() && !stop_)
            cv_.wait(lock); //With notify we get the lock back

        //In case the stop condtions are both set we stoppin'
        if(stop_ && packet_q_.empty())
            return;
        //Else we do our job -> Copy the first packet in the q and pop it
        PacketData packet = packet_q_.front(); 
        packet_q_.pop();
       

        //Release the lock, we are done 
        lock.unlock();


        //To be fixed undefined identifier
        //process_dns_packet(packet.buffer, packet.len, packet.cliaddr, packet.clilen);

    }


}