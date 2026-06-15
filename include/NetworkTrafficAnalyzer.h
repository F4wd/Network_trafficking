#ifndef NETWORK_TRAFFIC_ANALYZER_H
#define NETWORK_TRAFFIC_ANALYZER_H

#include "Packet.h"
#include "PacketHashTable.h"
#include "PacketBTree.h"
#include "PacketMaxHeap.h"
#include <memory>
// #include <mutex>
#include <vector>
#include <algorithm>
#include <map>

class NetworkTrafficAnalyzer {
private:
    PacketHashTable hashTable;
    PacketBTree<5> btree;
    PacketMaxHeap maxHeap;
    // std::mutex dataMutex;
    size_t totalPackets;

public:
    NetworkTrafficAnalyzer() : totalPackets(0) {}

    // Add a packet to all data structures
    void addPacket(std::shared_ptr<Packet> packet) {
        // std::lock_guard<std::mutex> lock(dataMutex);

        // Insert into hash table with multiple keys for different lookups
        hashTable.insert("SRC:" + packet->sourceIP, packet);
        hashTable.insert("DST:" + packet->destIP, packet);
        hashTable.insert("PROTO:" + protocolToString(packet->protocol), packet);
        
        // Insert into B-tree for timestamp indexing
        btree.insert(packet);
        
        // Insert into max heap for size tracking
        maxHeap.insert(packet);
        
        totalPackets++;
    }

    // Query: Get top K largest packets
    std::vector<std::shared_ptr<Packet>> getTopKLargestPackets(int k) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        return maxHeap.getTopK(k);
    }

    // Query: Get packets within a time range
    std::vector<std::shared_ptr<Packet>> getPacketsInTimeRange(
        long long startTimeMs, long long endTimeMs) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        return btree.rangeQuery(startTimeMs, endTimeMs);
    }

    // Query: Get packets by source IP
    std::vector<std::shared_ptr<Packet>> getPacketsBySourceIP(const std::string& ip) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        return hashTable.findBySourceIP(ip);
    }

    // Query: Get packets by destination IP
    std::vector<std::shared_ptr<Packet>> getPacketsByDestIP(const std::string& ip) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        return hashTable.findByDestIP(ip);
    }

    // Query: Get packets by protocol
    std::vector<std::shared_ptr<Packet>> getPacketsByProtocol(Protocol proto) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        return hashTable.findByProtocol(proto);
    }

    // Query: Get packets filtered by IP and protocol
    std::vector<std::shared_ptr<Packet>> getPacketsByIPAndProtocol(
        const std::string& ip, Protocol proto, bool isSourceIP = true) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        
        // Get packets by IP
        auto ipPackets = isSourceIP ? 
            hashTable.findBySourceIP(ip) : 
            hashTable.findByDestIP(ip);
        
        // Filter by protocol
        std::vector<std::shared_ptr<Packet>> results;
        for (const auto& packet : ipPackets) {
            if (packet->protocol == proto) {
                results.push_back(packet);
            }
        }
        
        return results;
    }

    // Query: Get top K largest packets in a time range
    std::vector<std::shared_ptr<Packet>> getTopKInTimeRange(
        int k, long long startTimeMs, long long endTimeMs) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        
        // Get packets in time range
        auto rangePackets = btree.rangeQuery(startTimeMs, endTimeMs);
        
        // Sort by size and get top K
        std::sort(rangePackets.begin(), rangePackets.end(),
            [](const std::shared_ptr<Packet>& a, const std::shared_ptr<Packet>& b) {
                return a->packetSize > b->packetSize;
            });
        
        if (rangePackets.size() > static_cast<size_t>(k)) {
            rangePackets.resize(k);
        }
        
        return rangePackets;
    }

    // Query: Get packets by protocol in time range
    std::vector<std::shared_ptr<Packet>> getPacketsByProtocolInTimeRange(
        Protocol proto, long long startTimeMs, long long endTimeMs) {
        // std::lock_guard<std::mutex> lock(dataMutex);
        
        // Get packets in time range
        auto rangePackets = btree.rangeQuery(startTimeMs, endTimeMs);
        
        // Filter by protocol
        std::vector<std::shared_ptr<Packet>> results;
        for (const auto& packet : rangePackets) {
            if (packet->protocol == proto) {
                results.push_back(packet);
            }
        }
        
        return results;
    }

    // Get all packets sorted by timestamp
    std::vector<std::shared_ptr<Packet>> getAllPacketsByTime() {
        // std::lock_guard<std::mutex> lock(dataMutex);
        return btree.getAllSorted();
    }

    // Get all packets sorted by size
    std::vector<std::shared_ptr<Packet>> getAllPacketsBySize() {
        // std::lock_guard<std::mutex> lock(dataMutex);
        return maxHeap.getAllSorted();
    }

    // Get statistics
    struct Statistics {
        size_t totalPackets;
        size_t totalBytes;
        double avgPacketSize;
        size_t largestPacketSize;
        size_t smallestPacketSize;
        std::map<Protocol, size_t> protocolCounts;
    };

    Statistics getStatistics() {
        // std::lock_guard<std::mutex> lock(dataMutex);
        
        Statistics stats;
        stats.totalPackets = totalPackets;
        stats.totalBytes = 0;
        stats.largestPacketSize = 0;
        stats.smallestPacketSize = SIZE_MAX;
        
        auto allPackets = btree.getAllSorted();
        
        for (const auto& packet : allPackets) {
            stats.totalBytes += packet->packetSize;
            stats.largestPacketSize = std::max(stats.largestPacketSize, packet->packetSize);
            stats.smallestPacketSize = std::min(stats.smallestPacketSize, packet->packetSize);
            stats.protocolCounts[packet->protocol]++;
        }
        
        stats.avgPacketSize = totalPackets > 0 ? 
            static_cast<double>(stats.totalBytes) / totalPackets : 0.0;
        
        if (totalPackets == 0) {
            stats.smallestPacketSize = 0;
        }
        
        return stats;
    }

    // Get total packet count
    size_t getTotalPackets() const {
        return totalPackets;
    }

    // Clear all data
    void clear() {
        // std::lock_guard<std::mutex> lock(dataMutex);
        hashTable.clear();
        maxHeap.clear();
        totalPackets = 0;
    }
};

#endif // NETWORK_TRAFFIC_ANALYZER_H
