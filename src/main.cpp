#include "NetworkTrafficAnalyzer.h"
#include "PacketGenerator.h"
#include "PacketLogger.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <map>

// Thread support detection
#ifdef _WIN32
    #include <windows.h>
    #define HAS_THREADS 1
#else
    #ifdef __MINGW32__
        // MinGW might not have proper thread support
        #ifdef _GLIBCXX_HAS_GTHREADS
            #include <thread>
            #include <atomic>
            #define HAS_THREADS 1
        #else
            #define HAS_THREADS 0
        #endif
    #else
        #include <thread>
        #include <atomic>
        #define HAS_THREADS 1
    #endif
#endif

// Windows thread implementation
#ifdef _WIN32
class NetworkTrafficVisualizer {
private:
    NetworkTrafficAnalyzer analyzer;
    PacketGenerator generator;
    PacketLogger logger;
    volatile bool running;
    HANDLE generatorThread;
    int packetsPerSecond;
    
    static DWORD WINAPI generatorThreadFunc(LPVOID param) {
        NetworkTrafficVisualizer* self = (NetworkTrafficVisualizer*)param;
        std::cout << "[Simulation Thread] Started generating " 
                  << self->packetsPerSecond << " packets/second\n";
        
        DWORD interval = 1000 / self->packetsPerSecond;
        int counter = 0;
        
        while (self->running) {
            auto packet = self->generator.generatePacket();
            self->analyzer.addPacket(packet);
            
            if (++counter % self->packetsPerSecond == 0) {
                std::cout << "[Simulation] Generated " << counter 
                          << " packets...\n";
            }
            
            Sleep(interval);
        }
        
        std::cout << "[Simulation Thread] Stopped\n";
        return 0;
    }

public:
    NetworkTrafficVisualizer() : running(false), generatorThread(NULL), packetsPerSecond(10) {}

    ~NetworkTrafficVisualizer() {
        stopSimulation();
    }

    // Start packet generation simulation
    void startSimulation(int pps = 10) {
        if (running) {
            std::cout << "Simulation is already running.\n";
            return;
        }
        
        packetsPerSecond = pps;
        running = true;
        
        generatorThread = CreateThread(NULL, 0, generatorThreadFunc, this, 0, NULL);
        if (generatorThread == NULL) {
            std::cout << "Failed to create thread!\n";
            running = false;
            return;
        }
        
        std::cout << "Real-time simulation started (" << pps << " packets/sec)\n";
    }

    // Stop packet generation
    void stopSimulation() {
        if (!running) {
            std::cout << "No simulation is currently running.\n";
            return;
        }
        
        std::cout << "Stopping simulation...\n";
        running = false;
        
        if (generatorThread != NULL) {
            WaitForSingleObject(generatorThread, INFINITE);
            CloseHandle(generatorThread);
            generatorThread = NULL;
        }
        
        std::cout << "Simulation stopped.\n";
    }
#else
// Fallback for non-Windows or no thread support
class NetworkTrafficVisualizer {
private:
    NetworkTrafficAnalyzer analyzer;
    PacketGenerator generator;
    PacketLogger logger;
    bool running;
    int packetsPerSecond;

public:
    NetworkTrafficVisualizer() : running(false), packetsPerSecond(10) {}

    ~NetworkTrafficVisualizer() {
        stopSimulation();
    }

    // Start packet generation simulation
    void startSimulation(int pps = 10) {
        std::cout << "Note: Real-time threading not available on this system.\n";
        std::cout << "Use option 8 to generate batch packets instead.\n";
    }

    // Stop packet generation
    void stopSimulation() {
        std::cout << "No simulation to stop.\n";
    }
#endif

    // Query: Top K largest packets
    void queryTopKPackets(int k) {
        auto results = analyzer.getTopKLargestPackets(k);
        
        std::cout << "\n=== Top " << k << " Largest Packets ===\n";
        for (size_t i = 0; i < results.size(); i++) {
            std::cout << (i + 1) << ". " << results[i]->toString() << "\n";
        }
        std::cout << "===================================\n";
        
        logger.logQueryResult("Top " + std::to_string(k) + " Largest Packets", results);
    }

    // Query: Packets in time range
    void queryTimeRange(int secondsAgo, int duration) {
        auto now = std::chrono::system_clock::now();
        auto startTime = now - std::chrono::seconds(secondsAgo + duration);
        auto endTime = now - std::chrono::seconds(secondsAgo);
        
        long long startMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            startTime.time_since_epoch()).count();
        long long endMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime.time_since_epoch()).count();
        
        auto results = analyzer.getPacketsInTimeRange(startMs, endMs);
        
        std::cout << "\n=== Packets in last " << (secondsAgo + duration) 
                  << " to " << secondsAgo << " seconds ===\n";
        std::cout << "Found " << results.size() << " packets:\n";
        
        int count = 0;
        for (const auto& packet : results) {
            std::cout << packet->toString() << "\n";
            if (++count >= 20) {
                std::cout << "... (showing first 20 of " << results.size() << ")\n";
                break;
            }
        }
        std::cout << "================================\n";
        
        logger.logQueryResult("Time Range Query", results);
    }

    // Query: Packets by protocol
    void queryByProtocol(Protocol proto) {
        auto results = analyzer.getPacketsByProtocol(proto);
        
        std::cout << "\n=== Packets with Protocol: " << protocolToString(proto) << " ===\n";
        std::cout << "Found " << results.size() << " packets:\n";
        
        int count = 0;
        for (const auto& packet : results) {
            std::cout << packet->toString() << "\n";
            if (++count >= 20) {
                std::cout << "... (showing first 20 of " << results.size() << ")\n";
                break;
            }
        }
        std::cout << "=====================================\n";
        
        logger.logQueryResult("Protocol: " + protocolToString(proto), results);
    }

    // Query: Packets by source IP
    void queryBySourceIP(const std::string& ip) {
        auto results = analyzer.getPacketsBySourceIP(ip);
        
        std::cout << "\n=== Packets from Source IP: " << ip << " ===\n";
        std::cout << "Found " << results.size() << " packets:\n";
        
        for (const auto& packet : results) {
            std::cout << packet->toString() << "\n";
        }
        std::cout << "=====================================\n";
        
        logger.logQueryResult("Source IP: " + ip, results);
    }

    // Display statistics
    void displayStatistics() {
        auto stats = analyzer.getStatistics();
        
        std::stringstream ss;
        ss << "\n=== Network Traffic Statistics ===\n";
        ss << "Total Packets: " << stats.totalPackets << "\n";
        ss << "Total Bytes: " << stats.totalBytes << " bytes\n";
        ss << "Average Packet Size: " << std::fixed << std::setprecision(2) 
           << stats.avgPacketSize << " bytes\n";
        ss << "Largest Packet: " << stats.largestPacketSize << " bytes\n";
        ss << "Smallest Packet: " << stats.smallestPacketSize << " bytes\n";
        ss << "\nProtocol Distribution:\n";
        
        for (const auto& pair : stats.protocolCounts) {
            double percentage = (static_cast<double>(pair.second) / stats.totalPackets) * 100.0;
            ss << "  " << std::setw(8) << std::left << protocolToString(pair.first) 
               << ": " << std::setw(6) << pair.second 
               << " (" << std::fixed << std::setprecision(1) 
               << percentage << "%)\n";
        }
        ss << "==================================\n";
        
        std::string output = ss.str();
        std::cout << output;
        logger.logStatistics(output);
    }

    // Initialize logger
    bool initLogger(const std::string& filepath) {
        return logger.open(filepath);
    }

    // Get analyzer reference
    NetworkTrafficAnalyzer& getAnalyzer() {
        return analyzer;
    }

    // Get generator reference
    PacketGenerator& getGenerator() {
        return generator;
    }

    // Generate initial batch of packets
    void generateInitialPackets(size_t count) {
        std::cout << "Generating " << count << " initial packets...\n";
        
        for (size_t i = 0; i < count; i++) {
            auto packet = generator.generatePacket();
            analyzer.addPacket(packet);
            
            // Small delay to spread timestamps
#ifdef _WIN32
            Sleep(10);
#else
            // No delay without threading
#endif
        }
        
        std::cout << "Initial packet generation complete.\n";
    }
};

// Display menu
void displayMenu() {
    std::cout << "\n===== Network Traffic Visualizer =====\n";
    std::cout << "1. Start real-time simulation\n";
    std::cout << "2. Stop simulation\n";
    std::cout << "3. Query top-K largest packets\n";
    std::cout << "4. Query packets in time range\n";
    std::cout << "5. Query packets by protocol\n";
    std::cout << "6. Query packets by source IP\n";
    std::cout << "7. Display statistics\n";
    std::cout << "8. Generate batch packets\n";
    std::cout << "9. Exit\n";
    std::cout << "======================================\n";
    std::cout << "Enter choice: ";
}

int main() {
    NetworkTrafficVisualizer visualizer;
    
    // Initialize logger
    std::string logFile = "network_traffic_log.txt";
    if (visualizer.initLogger(logFile)) {
        std::cout << "Logger initialized: " << logFile << "\n";
    } else {
        std::cout << "Warning: Could not open log file.\n";
    }

    // Generate some initial packets
    visualizer.generateInitialPackets(70);
    visualizer.displayStatistics();

    bool running = true;
    while (running) {
        displayMenu();
        
        int choice;
        std::cin >> choice;
        
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << "Invalid input. Please enter a number.\n";
            continue;
        }

        switch (choice) {
            case 1: {
                int pps;
                std::cout << "Enter packets per second (1-100): ";
                std::cin >> pps;
                if (pps < 1) pps = 1;
                if (pps > 100) pps = 100;
                visualizer.startSimulation(pps);
                break;
            }
            
            case 2:
                visualizer.stopSimulation();
                break;
            
            case 3: {
                int k;
                std::cout << "Enter K (number of largest packets): ";
                std::cin >> k;
                visualizer.queryTopKPackets(k);
                break;
            }
            
            case 4: {
                int secondsAgo, duration;
                std::cout << "Enter seconds ago to start: ";
                std::cin >> secondsAgo;
                std::cout << "Enter duration in seconds: ";
                std::cin >> duration;
                visualizer.queryTimeRange(secondsAgo, duration);
                break;
            }
            
            case 5: {
                std::cout << "Select protocol:\n";
                std::cout << "0-TCP, 1-UDP, 2-ICMP, 3-HTTP, 4-HTTPS, 5-DNS, 6-FTP, 7-SSH\n";
                std::cout << "Enter number: ";
                int protoNum;
                std::cin >> protoNum;
                if (protoNum >= 0 && protoNum <= 7) {
                    visualizer.queryByProtocol(static_cast<Protocol>(protoNum));
                } else {
                    std::cout << "Invalid protocol number.\n";
                }
                break;
            }
            
            case 6: {
                std::string ip;
                std::cout << "Enter source IP address: ";
                std::cin >> ip;
                visualizer.queryBySourceIP(ip);
                break;
            }
            
            case 7:
                visualizer.displayStatistics();
                break;
            
            case 8: {
                int count;
                std::cout << "Enter number of packets to generate: ";
                std::cin >> count;
                visualizer.generateInitialPackets(count);
                break;
            }
            
            case 9:
                visualizer.stopSimulation();
                std::cout << "Exiting...\n";
                running = false;
                break;
            
            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }

    return 0;
}

struct Statistics {
    // ...existing code...
    std::map<Protocol, int> protocolCounts;
    // ...existing code...
};
