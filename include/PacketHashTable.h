#ifndef PACKET_HASH_TABLE_H
#define PACKET_HASH_TABLE_H

#include "Packet.h"
#include <vector>
#include <list>
#include <functional>
#include <memory>

class PacketHashTable {
private:
    static const size_t DEFAULT_SIZE = 1024;
    static constexpr double LOAD_FACTOR_THRESHOLD = 0.75;

    struct Entry {
        std::string key;
        std::shared_ptr<Packet> packet;
        Entry(const std::string& k, std::shared_ptr<Packet> p) : key(k), packet(p) {}
    };

    std::vector<std::list<Entry>> table;
    size_t numElements;
    size_t tableSize;

    // Hash function for strings
    size_t hash(const std::string& key) const {
        std::hash<std::string> hasher;
        return hasher(key) % tableSize;
    }

    // Rehash when load factor is too high
    void rehash() {
        size_t newSize = tableSize * 2;
        std::vector<std::list<Entry>> newTable(newSize);
        
        for (auto& bucket : table) {
            for (auto& entry : bucket) {
                size_t newIndex = std::hash<std::string>{}(entry.key) % newSize;
                newTable[newIndex].push_back(entry);
            }
        }
        
        table = std::move(newTable);
        tableSize = newSize;
    }

public:
    PacketHashTable(size_t size = DEFAULT_SIZE) 
        : table(size), numElements(0), tableSize(size) {}

    // Insert a packet with a key (IP address or protocol)
    void insert(const std::string& key, std::shared_ptr<Packet> packet) {
        // Check load factor
        if (static_cast<double>(numElements) / tableSize > LOAD_FACTOR_THRESHOLD) {
            rehash();
        }

        size_t index = hash(key);
        table[index].emplace_back(key, packet);
        numElements++;
    }

    // Find all packets matching a key
    std::vector<std::shared_ptr<Packet>> find(const std::string& key) const {
        std::vector<std::shared_ptr<Packet>> results;
        size_t index = hash(key);
        
        for (const auto& entry : table[index]) {
            if (entry.key == key) {
                results.push_back(entry.packet);
            }
        }
        
        return results;
    }

    // Find packets by source IP
    std::vector<std::shared_ptr<Packet>> findBySourceIP(const std::string& ip) const {
        return find("SRC:" + ip);
    }

    // Find packets by destination IP
    std::vector<std::shared_ptr<Packet>> findByDestIP(const std::string& ip) const {
        return find("DST:" + ip);
    }

    // Find packets by protocol
    std::vector<std::shared_ptr<Packet>> findByProtocol(Protocol proto) const {
        return find("PROTO:" + protocolToString(proto));
    }

    // Get total number of elements
    size_t size() const {
        return numElements;
    }

    // Clear all entries
    void clear() {
        for (auto& bucket : table) {
            bucket.clear();
        }
        numElements = 0;
    }

    // Get load factor
    double getLoadFactor() const {
        return static_cast<double>(numElements) / tableSize;
    }
};

#endif // PACKET_HASH_TABLE_H
