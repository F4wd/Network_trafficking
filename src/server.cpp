#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "NetworkTrafficAnalyzer.h"
#include "PacketGenerator.h"
#include "PacketLogger.h"
#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>
#include <memory>
#include <chrono>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 8192
#define DEFAULT_PORT "9999"

// Global analyzer and generator
NetworkTrafficAnalyzer analyzer;
PacketGenerator generator;
bool serverRunning = true;

// Thread function for packet generation
DWORD WINAPI simulationThread(LPVOID param) {
    std::cout << "[Server] Packet generation thread started\n";
    int counter = 0;
    
    while (serverRunning) {
        auto packet = generator.generatePacket();
        analyzer.addPacket(packet);
        
        if (++counter % 10 == 0) {
            std::cout << "[Server] Generated " << counter << " packets\n";
        }
        
        Sleep(50);
    }
    
    std::cout << "[Server] Packet generation thread stopped\n";
    return 0;
}

// Parse protocol string to enum
Protocol parseProtocol(const std::string& protoStr) {
    if (protoStr == "TCP") return Protocol::TCP;
    if (protoStr == "UDP") return Protocol::UDP;
    if (protoStr == "ICMP") return Protocol::ICMP;
    if (protoStr == "HTTP") return Protocol::HTTP;
    if (protoStr == "HTTPS") return Protocol::HTTPS;
    if (protoStr == "DNS") return Protocol::DNS;
    if (protoStr == "FTP") return Protocol::FTP;
    if (protoStr == "SSH") return Protocol::SSH;
    return Protocol::TCP;
}

// Process client request and return response
std::string processRequest(const std::string& request) {
    std::istringstream iss(request);
    std::string command;
    iss >> command;
    
    try {
        if (command == "HELP") {
            return R"(
Available Commands:
  HELP                                    - Show this help message
  TOP_K <k>                              - Get top K largest packets
  TIME_RANGE <start_ms> <end_ms>         - Get packets in time range
  SOURCE_IP <ip>                         - Get packets from source IP
  DEST_IP <ip>                           - Get packets to destination IP
  PROTOCOL <protocol>                    - Get packets by protocol (TCP,UDP,ICMP,HTTP,HTTPS,DNS,FTP,SSH)
  IP_PROTOCOL <ip> <protocol> [source]   - Get packets by IP and protocol (source=true if 3rd arg exists)
  TOP_K_RANGE <k> <start_ms> <end_ms>   - Get top K packets in time range
  PROTO_RANGE <protocol> <start_ms> <end_ms> - Get packets by protocol in time range
  ALL_TIME                               - Get all packets sorted by time
  ALL_SIZE                               - Get all packets sorted by size
  STATS                                  - Get traffic statistics
)";
        }
        
        else if (command == "TOP_K") {
            int k;
            if (!(iss >> k)) return "ERROR: TOP_K requires an integer argument";
            
            auto packets = analyzer.getTopKLargestPackets(k);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " packets:\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "TIME_RANGE") {
            long long start, end;
            if (!(iss >> start >> end)) return "ERROR: TIME_RANGE requires two millisecond values";
            
            auto packets = analyzer.getPacketsInTimeRange(start, end);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " packets:\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "SOURCE_IP") {
            std::string ip;
            if (!(iss >> ip)) return "ERROR: SOURCE_IP requires an IP address";
            
            auto packets = analyzer.getPacketsBySourceIP(ip);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " packets from " << ip << ":\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "DEST_IP") {
            std::string ip;
            if (!(iss >> ip)) return "ERROR: DEST_IP requires an IP address";
            
            auto packets = analyzer.getPacketsByDestIP(ip);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " packets to " << ip << ":\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "PROTOCOL") {
            std::string protoStr;
            if (!(iss >> protoStr)) return "ERROR: PROTOCOL requires a protocol name";
            
            Protocol proto = parseProtocol(protoStr);
            auto packets = analyzer.getPacketsByProtocol(proto);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " " << protoStr << " packets:\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "IP_PROTOCOL") {
            std::string ip, protoStr;
            std::string sourceStr;
            if (!(iss >> ip >> protoStr)) 
                return "ERROR: IP_PROTOCOL requires an IP and protocol";
            
            iss >> sourceStr; // Optional third parameter
            bool isSourceIP = sourceStr.empty() || sourceStr == "source";
            
            Protocol proto = parseProtocol(protoStr);
            auto packets = analyzer.getPacketsByIPAndProtocol(ip, proto, isSourceIP);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " packets with IP " << ip 
                << " and protocol " << protoStr << ":\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "TOP_K_RANGE") {
            int k;
            long long start, end;
            if (!(iss >> k >> start >> end)) 
                return "ERROR: TOP_K_RANGE requires k, start_ms, and end_ms";
            
            auto packets = analyzer.getTopKInTimeRange(k, start, end);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " top " << k << " packets in range:\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "PROTO_RANGE") {
            std::string protoStr;
            long long start, end;
            if (!(iss >> protoStr >> start >> end)) 
                return "ERROR: PROTO_RANGE requires protocol, start_ms, and end_ms";
            
            Protocol proto = parseProtocol(protoStr);
            auto packets = analyzer.getPacketsByProtocolInTimeRange(proto, start, end);
            std::ostringstream oss;
            oss << "Found " << packets.size() << " " << protoStr << " packets in range:\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "ALL_TIME") {
            auto packets = analyzer.getAllPacketsByTime();
            std::ostringstream oss;
            oss << "All " << packets.size() << " packets (sorted by time):\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "ALL_SIZE") {
            auto packets = analyzer.getAllPacketsBySize();
            std::ostringstream oss;
            oss << "All " << packets.size() << " packets (sorted by size):\n";
            for (const auto& pkt : packets) {
                oss << "  " << pkt->toString() << "\n";
            }
            return oss.str();
        }
        
        else if (command == "STATS") {
            auto stats = analyzer.getStatistics();
            std::ostringstream oss;
            oss << "=== Traffic Statistics ===\n"
                << "Total Packets: " << stats.totalPackets << "\n"
                << "Total Bytes: " << stats.totalBytes << "\n"
                << "Average Size: " << stats.avgPacketSize << " bytes\n";
            
            // Display protocol counts
            for (const auto& pc : stats.protocolCounts) {
                oss << protocolToString(pc.first) << " Packets: " << pc.second << "\n";
            }
            
            return oss.str();
        }
        
        else {
            return "ERROR: Unknown command. Type 'HELP' for available commands.";
        }
    }
    catch (const std::exception& e) {
        return std::string("ERROR: ") + e.what();
    }
}

// Handle client connection
void handleClient(SOCKET clientSocket, int clientId) {
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    
    std::cout << "[Server] Client " << clientId << " connected\n";
    
    // Send welcome message
    const char* welcomeMsg = "Welcome to Network Traffic Analyzer Server\nType 'HELP' for commands\n";
    send(clientSocket, welcomeMsg, (int)strlen(welcomeMsg), 0);
    
    // Receive and process requests
    while (serverRunning) {
        iResult = recv(clientSocket, recvbuf, DEFAULT_BUFLEN - 1, 0);
        
        if (iResult > 0) {
            recvbuf[iResult] = '\0';
            std::string request(recvbuf);
            
            // Remove newline characters
            request.erase(std::remove(request.begin(), request.end(), '\n'), request.end());
            request.erase(std::remove(request.begin(), request.end(), '\r'), request.end());
            
            std::cout << "[Server] Client " << clientId << " request: " << request << "\n";
            
            if (request == "EXIT" || request == "QUIT") {
                const char* msg = "Goodbye!\n";
                send(clientSocket, msg, (int)strlen(msg), 0);
                break;
            }
            
            // Process request and send response
            std::string response = processRequest(request);
            
            // Send response (handle large responses by splitting)
            size_t offset = 0;
            while (offset < response.length()) {
                size_t chunkSize = (response.length() - offset < (size_t)DEFAULT_BUFLEN - 1) ? response.length() - offset : (size_t)DEFAULT_BUFLEN - 1;
                iResult = send(clientSocket, response.c_str() + offset, (int)chunkSize, 0);
                
                if (iResult == SOCKET_ERROR) {
                    std::cerr << "[Server] Send failed: " << WSAGetLastError() << "\n";
                    closesocket(clientSocket);
                    std::cout << "[Server] Client " << clientId << " disconnected\n";
                    return;
                }
                
                offset += iResult;
            }
            
            // Send delimiter
            send(clientSocket, "\n---END---\n", 10, 0);
        }
        else if (iResult == 0) {
            std::cout << "[Server] Client " << clientId << " closed connection\n";
            break;
        }
        else {
            std::cerr << "[Server] Recv failed: " << WSAGetLastError() << "\n";
            break;
        }
    }
    
    closesocket(clientSocket);
    std::cout << "[Server] Client " << clientId << " disconnected\n";
}

// Client thread parameters
struct ClientThreadParams {
    SOCKET socket;
    int clientId;
};

// Client thread wrapper
DWORD WINAPI clientThreadFunc(LPVOID param) {
    ClientThreadParams* params = (ClientThreadParams*)param;
    handleClient(params->socket, params->clientId);
    delete params;
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    
    // Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << "\n";
        return 1;
    }
    
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    
    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << "\n";
        WSACleanup();
        return 1;
    }
    
    // Create a SOCKET for connecting to server
    listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << "\n";
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    
    // Setup the TCP listening socket
    iResult = bind(listenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << "\n";
        freeaddrinfo(result);
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    freeaddrinfo(result);
    
    iResult = listen(listenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "listen failed: " << WSAGetLastError() << "\n";
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    std::cout << "========================================\n";
    std::cout << "Network Traffic Analyzer - SERVER\n";
    std::cout << "========================================\n";
    std::cout << "Listening on port " << DEFAULT_PORT << "...\n\n";
    
    // Start packet generation thread
    HANDLE simThread = CreateThread(NULL, 0, simulationThread, NULL, 0, NULL);
    if (simThread == NULL) {
        std::cerr << "Failed to create simulation thread\n";
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    int clientId = 0;
    
    // Accept client connections
    while (serverRunning) {
        clientSocket = accept(listenSocket, NULL, NULL);
        
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "accept failed: " << WSAGetLastError() << "\n";
            continue;
        }
        
        // Handle client in a separate thread
        clientId++;
        ClientThreadParams* params = new ClientThreadParams;
        params->socket = clientSocket;
        params->clientId = clientId;
        
        HANDLE clientThread = CreateThread(NULL, 0, clientThreadFunc, params, 0, NULL);
        
        if (clientThread) CloseHandle(clientThread);
    }
    
    // Cleanup
    serverRunning = false;
    closesocket(listenSocket);
    
    if (simThread) {
        WaitForSingleObject(simThread, INFINITE);
        CloseHandle(simThread);
    }
    
    WSACleanup();
    
    return 0;
}
