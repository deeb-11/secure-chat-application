#include <iostream>
#include <cstring>
#include <vector> // Include the <vector> header
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

constexpr int PORT = 4500;
constexpr int BUFFER_SIZE = 1024;

// Define a structure to hold user credentials
struct User {
    std::string username;
    std::string password;
};

// Function to authenticate user credentials
bool authenticateUser(const std::string& username, const std::string& password, const std::vector<User>& users) {
    for (const auto& user : users) {
        if (user.username == username && user.password == password) {
            return true;
        }
    }
    return false;
}

int main() {
    int serverSocket, clientSocket;
    sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    // Create socket
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return 1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(PORT);

    // Bind socket to port
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        return 1;
    }

    // Listen for connections
    if (listen(serverSocket, 1) < 0) {
        std::cerr << "Listen failed" << std::endl;
        return 1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    // Define user accounts
    std::vector<User> users = {
        {"deeb", "deeb123"},
        {"server", "server_admin"}
    };

    // Accept incoming connection
    if ((clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen)) < 0) {
        std::cerr << "Accept failed" << std::endl;
        return 1;
    }

    std::cout << "Client connected" << std::endl;

    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        if (recv(clientSocket, buffer, BUFFER_SIZE, 0) <= 0) {
            std::cout << "Connection closed by client." << std::endl;
            break;
        }
        std::cout << "deeb: " << buffer << std::endl;

        // Check if the received message is a login command
        if (strncmp(buffer, "LOGIN:", 6) == 0) {
            // Extract username and password from the message
            std::string loginInfo = buffer + 6; // Skip "LOGIN:"
            size_t delimiterPos = loginInfo.find(':');
            if (delimiterPos != std::string::npos) {
                std::string username = loginInfo.substr(0, delimiterPos);
                std::string password = loginInfo.substr(delimiterPos + 1);

                // Authenticate user credentials
                if (authenticateUser(username, password, users)) {
                    send(clientSocket, "Login successful", 16, 0);
                    std::cout << "Login successful" << std::endl;
                } else {
                    send(clientSocket, "Login failed", 12, 0);
                    std::cout << "Login failed" << std::endl;
                    close(clientSocket);
                    return 1; // Exit the program if login fails
                }
            }
        } else {
            std::cout << "Server: ";
            std::cin.getline(buffer, BUFFER_SIZE);
            send(clientSocket, buffer, strlen(buffer), 0);
        }
    }

    close(clientSocket);
    close(serverSocket);

    return 0;
}
