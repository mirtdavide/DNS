#include "thread_pool.hpp"
#include "dns_handler.hpp"
#include "dns_protocol.hpp"
#include <iostream>

//Constructor
ThreadPool::ThreadPool(int num_threads){

    stop_ = false;
    for(int i = 0; i < num_threads; i++){
        //Create a thread that does the worker_loop function
        std::thread t(&ThreadPool::worker_loop,this);

        //Move said thread in a vector, TODO: try with only t to see what happens
        workers_.push_back(std::move(t));


    }


}
ThreadPool::~ThreadPool(){

    //Get the lock to set the shared variable
    std::unique_lock<std::mutex> lock(mtx_);

    //Set stop to true
    stop_ = true;

    //Release the lock
    lock.unlock();

    //Wakey wakey 
    cv_.notify_all();
    //Wait that everyone is done
    for (std::thread& t : workers_) {
        t.join();
    }
}

/*
Main Thread business, big boss does this
Puts a copy of the packet in the queue and wakes one worker.
*/
void ThreadPool::push(const PacketData& packet) {

    //Get the lock to write on q
    std::unique_lock<std::mutex> lock(mtx_);

    //Push the packet on q
    packet_q_.push(packet);

    //Release lock
    lock.unlock();

    //call one slave
    cv_.notify_one();
}

//This is what our workers do until they are dead :)
void ThreadPool::worker_loop(){
    std::cout << "Worker started" << std::endl;

    while(true){

        //Get the lock on the mutex, it is now our turn
        std::unique_lock<std::mutex> lock(mtx_);
        
        //While the q is empty or the stop condition is set the thread releases the lock and waits to be called with notify_one
        while(packet_q_.empty() && !stop_)
            cv_.wait(lock); //With notify we get the lock back

        //In case the stop condtions are both set we stoppin'
        if(stop_ && packet_q_.empty()){
            std::cout << "Worker shutting down" << std::endl;
            return;
        }
        std::cout << "Worker picked up a packet, processing..." << std::endl;
        //Else we do our job -> Copy the first packet in the q and pop it
        PacketData packet = packet_q_.front(); 
        packet_q_.pop();
       

        //Release the lock, we are done 
        lock.unlock();


        //To be fixed undefined identifier
        process_dns_packet(packet.buffer, packet.len, packet.sock, packet.cliaddr, packet.clilen);
        std::cout << "Worker done, going back to sleep" << std::endl;
    }


}