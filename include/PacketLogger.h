#ifndef PACKET_LOGGER_H
#define PACKET_LOGGER_H

#include "Packet.h"
#include <fstream>
#include <string>
#include <memory>
// #include <mutex>
#include <iomanip>

class PacketLogger {
private:
    std::ofstream logFile;
    std::string logFilePath;
    // std::mutex logMutex;
    bool isOpen;

public:
    PacketLogger() : isOpen(false) {}

    ~PacketLogger() {
        close();
    }

    // Open log file
    bool open(const std::string& filepath) {
        // std::lock_guard<std::mutex> lock(logMutex);
        
        logFilePath = filepath;
        logFile.open(filepath, std::ios::out | std::ios::app);
        
        if (logFile.is_open()) {
            isOpen = true;
            // Write header
            logFile << "=================================================\n";
            logFile << "Network Traffic Log\n";
            logFile << "Started: " << getCurrentTime() << "\n";
            logFile << "=================================================\n";
            logFile.flush();
            return true;
        }
        
        return false;
    }

    // Close log file
    void close() {
        // std::lock_guard<std::mutex> lock(logMutex);
        if (isOpen && logFile.is_open()) {
            logFile << "=================================================\n";
            logFile << "Log closed: " << getCurrentTime() << "\n";
            logFile << "=================================================\n";
            logFile.close();
            isOpen = false;
        }
    }

    // Log a single packet
    void logPacket(const Packet& packet) {
        if (!isOpen) return;
        
        // std::lock_guard<std::mutex> lock(logMutex);
        logFile << packet.toString() << "\n";
        logFile.flush();
    }

    // Log a single packet (shared_ptr version)
    void logPacket(const std::shared_ptr<Packet>& packet) {
        if (packet) {
            logPacket(*packet);
        }
    }

    // Log multiple packets
    void logPackets(const std::vector<std::shared_ptr<Packet>>& packets) {
        if (!isOpen) return;
        
        // std::lock_guard<std::mutex> lock(logMutex);
        for (const auto& packet : packets) {
            if (packet) {
                logFile << packet->toString() << "\n";
            }
        }
        logFile.flush();
    }

    // Log a message
    void logMessage(const std::string& message) {
        if (!isOpen) return;
        
        // std::lock_guard<std::mutex> lock(logMutex);
        logFile << "[" << getCurrentTime() << "] " << message << "\n";
        logFile.flush();
    }

    // Log query results
    void logQueryResult(const std::string& queryName, 
                       const std::vector<std::shared_ptr<Packet>>& results) {
        if (!isOpen) return;
        
        // std::lock_guard<std::mutex> lock(logMutex);
        logFile << "\n--- Query: " << queryName << " ---\n";
        logFile << "Results: " << results.size() << " packets\n";
        
        for (const auto& packet : results) {
            if (packet) {
                logFile << "  " << packet->toString() << "\n";
            }
        }
        
        logFile << "--- End Query ---\n\n";
        logFile.flush();
    }

    // Log statistics
    void logStatistics(const std::string& stats) {
        if (!isOpen) return;
        
        // std::lock_guard<std::mutex> lock(logMutex);
        logFile << "\n=== Statistics ===\n";
        logFile << stats;
        logFile << "==================\n\n";
        logFile.flush();
    }

    // Check if logger is open
    bool isLogOpen() const {
        return isOpen;
    }

    // Get log file path
    std::string getLogFilePath() const {
        return logFilePath;
    }

private:
    // Get current time as string
    std::string getCurrentTime() const {
        auto now = std::chrono::system_clock::now();
        auto time_t_val = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t_val), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

#endif // PACKET_LOGGER_H
