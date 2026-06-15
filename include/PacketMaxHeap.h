#ifndef PACKET_MAX_HEAP_H
#define PACKET_MAX_HEAP_H

#include "Packet.h"
#include <vector>
#include <memory>
#include <algorithm>

class PacketMaxHeap {
private:
    std::vector<std::shared_ptr<Packet>> heap;

    // Get parent index
    int parent(int i) const {
        return (i - 1) / 2;
    }

    // Get left child index
    int leftChild(int i) const {
        return 2 * i + 1;
    }

    // Get right child index
    int rightChild(int i) const {
        return 2 * i + 2;
    }

    // Heapify up (bubble up)
    void heapifyUp(int index) {
        while (index > 0 && heap[parent(index)]->packetSize < heap[index]->packetSize) {
            std::swap(heap[parent(index)], heap[index]);
            index = parent(index);
        }
    }

    // Heapify down (bubble down)
    void heapifyDown(int index) {
        int largest = index;
        int left = leftChild(index);
        int right = rightChild(index);
        int size = heap.size();

        if (left < size && heap[left]->packetSize > heap[largest]->packetSize) {
            largest = left;
        }

        if (right < size && heap[right]->packetSize > heap[largest]->packetSize) {
            largest = right;
        }

        if (largest != index) {
            std::swap(heap[index], heap[largest]);
            heapifyDown(largest);
        }
    }

public:
    PacketMaxHeap() {}

    // Insert a packet into the heap
    void insert(std::shared_ptr<Packet> packet) {
        heap.push_back(packet);
        heapifyUp(heap.size() - 1);
    }

    // Get the maximum packet (largest size)
    std::shared_ptr<Packet> getMax() const {
        if (heap.empty()) {
            return nullptr;
        }
        return heap[0];
    }

    // Extract the maximum packet
    std::shared_ptr<Packet> extractMax() {
        if (heap.empty()) {
            return nullptr;
        }

        auto maxPacket = heap[0];
        heap[0] = heap.back();
        heap.pop_back();

        if (!heap.empty()) {
            heapifyDown(0);
        }

        return maxPacket;
    }

    // Get top K largest packets
    std::vector<std::shared_ptr<Packet>> getTopK(int k) {
        std::vector<std::shared_ptr<Packet>> result;
        
        // Create a copy of the heap
        std::vector<std::shared_ptr<Packet>> tempHeap = heap;
        PacketMaxHeap tempHeapObj;
        tempHeapObj.heap = tempHeap;

        // Extract k elements
        for (int i = 0; i < k && !tempHeapObj.empty(); i++) {
            result.push_back(tempHeapObj.extractMax());
        }

        return result;
    }

    // Get all packets sorted by size (descending)
    std::vector<std::shared_ptr<Packet>> getAllSorted() {
        std::vector<std::shared_ptr<Packet>> result;
        
        // Create a copy of the heap
        PacketMaxHeap tempHeap;
        tempHeap.heap = heap;

        while (!tempHeap.empty()) {
            result.push_back(tempHeap.extractMax());
        }

        return result;
    }

    // Check if heap is empty
    bool empty() const {
        return heap.empty();
    }

    // Get size of heap
    size_t size() const {
        return heap.size();
    }

    // Clear the heap
    void clear() {
        heap.clear();
    }

    // Build heap from vector of packets
    void buildHeap(const std::vector<std::shared_ptr<Packet>>& packets) {
        heap = packets;
        
        // Heapify from bottom up
        for (int i = heap.size() / 2 - 1; i >= 0; i--) {
            heapifyDown(i);
        }
    }

    // Get the underlying vector (for inspection)
    const std::vector<std::shared_ptr<Packet>>& getHeap() const {
        return heap;
    }
};

#endif // PACKET_MAX_HEAP_H
