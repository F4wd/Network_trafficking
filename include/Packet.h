#ifndef PACKET_H
#define PACKET_H

#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>

enum class Protocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    FTP,
    SSH
};

inline std::string protocolToString(Protocol proto) {
    switch(proto) {
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::HTTP: return "HTTP";
        case Protocol::HTTPS: return "HTTPS";
        case Protocol::DNS: return "DNS";
        case Protocol::FTP: return "FTP";
        case Protocol::SSH: return "SSH";
        default: return "UNKNOWN";
    }
}

struct Packet {
    std::string sourceIP;
    std::string destIP;
    size_t packetSize;
    std::chrono::system_clock::time_point timestamp;
    Protocol protocol;
    uint64_t packetId;

    Packet() : packetSize(0), protocol(Protocol::TCP), packetId(0) {
        timestamp = std::chrono::system_clock::now();
    }

    Packet(const std::string& src, const std::string& dst, size_t size, 
           Protocol proto, uint64_t id)
        : sourceIP(src), destIP(dst), packetSize(size), protocol(proto), packetId(id) {
        timestamp = std::chrono::system_clock::now();
    }

    // Get timestamp in milliseconds since epoch
    long long getTimestampMs() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()).count();
    }

    // Format timestamp as readable string
    std::string getFormattedTimestamp() const {
        auto time_t_val = std::chrono::system_clock::to_time_t(timestamp);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t_val), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    // Convert packet to string representation
    std::string toString() const {
        std::stringstream ss;
        ss << "Packet[ID:" << packetId 
           << ", " << sourceIP << "->" << destIP
           << ", Size:" << packetSize << "B"
           << ", Proto:" << protocolToString(protocol)
           << ", Time:" << getFormattedTimestamp() << "]";
        return ss.str();
    }

    // Comparison operators for heap operations
    bool operator<(const Packet& other) const {
        return packetSize < other.packetSize;
    }

    bool operator>(const Packet& other) const {
        return packetSize > other.packetSize;
    }
};

#endif // PACKET_H
