#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 8192
#define DEFAULT_PORT "9999"
#define DEFAULT_HOST "127.0.0.1"

int main(int argc, char* argv[]) {
    std::string host = DEFAULT_HOST;
    std::string port = DEFAULT_PORT;
    
    // Parse command line arguments
    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = argv[2];
    }
    
    WSADATA wsaData;
    SOCKET connectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    
    // Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << "\n";
        return 1;
    }
    
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    // Resolve the server address and port
    iResult = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << "\n";
        WSACleanup();
        return 1;
    }
    
    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        
        // Create a SOCKET for connecting to server
        connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (connectSocket == INVALID_SOCKET) {
            std::cerr << "socket failed: " << WSAGetLastError() << "\n";
            WSACleanup();
            return 1;
        }
        
        // Connect to server
        iResult = connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(connectSocket);
            connectSocket = INVALID_SOCKET;
            continue;
        }
        
        break;
    }
    
    freeaddrinfo(result);
    
    if (connectSocket == INVALID_SOCKET) {
        std::cerr << "Unable to connect to server on " << host << ":" << port << "\n";
        WSACleanup();
        return 1;
    }
    
    std::cout << "========================================\n";
    std::cout << "Network Traffic Analyzer - CLIENT\n";
    std::cout << "========================================\n";
    std::cout << "Connected to server at " << host << ":" << port << "\n";
    std::cout << "Type 'HELP' for available commands\n";
    std::cout << "Type 'EXIT' or 'QUIT' to disconnect\n\n";
    
    // Receive initial welcome message
    char recvbuf[DEFAULT_BUFLEN];
    iResult = recv(connectSocket, recvbuf, DEFAULT_BUFLEN - 1, 0);
    if (iResult > 0) {
        recvbuf[iResult] = '\0';
        std::cout << recvbuf;
    }
    
    std::string userInput;
    
    // Main interaction loop
    while (true) {
        std::cout << "\n> ";
        std::getline(std::cin, userInput);
        
        // Trim whitespace
        userInput.erase(0, userInput.find_first_not_of(" \t\r\n"));
        userInput.erase(userInput.find_last_not_of(" \t\r\n") + 1);
        
        if (userInput.empty()) {
            continue;
        }
        
        // Check for exit commands
        if (userInput == "EXIT" || userInput == "QUIT") {
            std::cout << "Disconnecting...\n";
            break;
        }
        
        // Send request to server
        iResult = send(connectSocket, userInput.c_str(), (int)userInput.length(), 0);
        if (iResult == SOCKET_ERROR) {
            std::cerr << "send failed: " << WSAGetLastError() << "\n";
            closesocket(connectSocket);
            WSACleanup();
            return 1;
        }
        
        // Send newline
        send(connectSocket, "\n", 1, 0);
        
        // Receive response
        std::cout << "\nServer Response:\n";
        std::cout << "----------------------------------------\n";
        
        bool receivingResponse = true;
        std::string fullResponse;
        
        while (receivingResponse) {
            iResult = recv(connectSocket, recvbuf, DEFAULT_BUFLEN - 1, 0);
            
            if (iResult > 0) {
                recvbuf[iResult] = '\0';
                std::string chunk(recvbuf);
                fullResponse += chunk;
                
                // Check for end delimiter
                if (fullResponse.find("---END---") != std::string::npos) {
                    // Remove the end delimiter
                    size_t endPos = fullResponse.find("---END---");
                    std::cout << fullResponse.substr(0, endPos);
                    receivingResponse = false;
                }
                else {
                    std::cout << chunk;
                }
            }
            else if (iResult == 0) {
                std::cout << "\nServer closed connection\n";
                receivingResponse = false;
                break;
            }
            else {
                std::cerr << "\nRecv failed: " << WSAGetLastError() << "\n";
                closesocket(connectSocket);
                WSACleanup();
                return 1;
            }
        }
        
        std::cout << "----------------------------------------\n";
    }
    
    // Send exit command
    send(connectSocket, "EXIT\n", 5, 0);
    
    // Cleanup
    closesocket(connectSocket);
    WSACleanup();
    
    return 0;
}
