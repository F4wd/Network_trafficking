#ifndef PACKET_GENERATOR_H
#define PACKET_GENERATOR_H

#include "Packet.h"
#include <random>
#include <memory>
#include <sstream>

class PacketGenerator {
private:
    std::mt19937 rng;
    std::uniform_int_distribution<int> ipOctet;
    std::uniform_int_distribution<int> protocolDist;
    std::uniform_int_distribution<int> sizeDist;
    uint64_t nextPacketId;

    // Generate a random IP address
    std::string generateIP() {
        std::stringstream ss;
        ss << ipOctet(rng) << "."
           << ipOctet(rng) << "."
           << ipOctet(rng) << "."
           << ipOctet(rng);
        return ss.str();
    }

    // Generate a random protocol
    Protocol generateProtocol() {
        int proto = protocolDist(rng);
        return static_cast<Protocol>(proto);
    }

    // Generate a random packet size (64 bytes to 65535 bytes)
    size_t generateSize() {
        return sizeDist(rng);
    }

public:
    PacketGenerator() 
        : rng(std::random_device{}()),
          ipOctet(1, 255),
          protocolDist(0, 7),  // 8 protocols
          sizeDist(64, 65535),
          nextPacketId(1) {}

    // Generate a single random packet
    std::shared_ptr<Packet> generatePacket() {
        auto packet = std::make_shared<Packet>(
            generateIP(),
            generateIP(),
            generateSize(),
            generateProtocol(),
            nextPacketId++
        );
        return packet;
    }

    // Generate multiple packets
    std::vector<std::shared_ptr<Packet>> generatePackets(size_t count) {
        std::vector<std::shared_ptr<Packet>> packets;
        packets.reserve(count);
        
        for (size_t i = 0; i < count; i++) {
            packets.push_back(generatePacket());
        }
        
        return packets;
    }

    // Generate a packet with specific source IP
    std::shared_ptr<Packet> generatePacketWithSourceIP(const std::string& sourceIP) {
        auto packet = std::make_shared<Packet>(
            sourceIP,
            generateIP(),
            generateSize(),
            generateProtocol(),
            nextPacketId++
        );
        return packet;
    }

    // Generate a packet with specific protocol
    std::shared_ptr<Packet> generatePacketWithProtocol(Protocol proto) {
        auto packet = std::make_shared<Packet>(
            generateIP(),
            generateIP(),
            generateSize(),
            proto,
            nextPacketId++
        );
        return packet;
    }

    // Generate a packet with specific size
    std::shared_ptr<Packet> generatePacketWithSize(size_t size) {
        auto packet = std::make_shared<Packet>(
            generateIP(),
            generateIP(),
            size,
            generateProtocol(),
            nextPacketId++
        );
        return packet;
    }

    // Reset packet ID counter
    void resetIdCounter() {
        nextPacketId = 1;
    }

    // Get next packet ID
    uint64_t getNextPacketId() const {
        return nextPacketId;
    }
};

#endif // PACKET_GENERATOR_H
