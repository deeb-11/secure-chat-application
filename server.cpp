#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

constexpr int PORT = 4500;
constexpr int BUFFER_SIZE = 1024;

// Structure to hold user credentials
struct User {
    std::string username;
    std::string password;
};

// Caesar cipher encryption function
std::string encrypt(const std::string& input, int key) {
    std::string result = input;
    for (char& c : result) {
        if (std::isalpha(c)) {
            char base = std::isupper(c) ? 'A' : 'a';
            c = (c - base + key) % 26 + base;
        }
    }
    return result;
}

// Function to authenticate user credentials
bool AuthenticateUser(const std::string& username, const std::string& password) {
    std::ifstream file("accounts.txt");
    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string fileUsername = line.substr(0, pos);
            std::string filePassword = line.substr(pos + 1);
            if (fileUsername == username && filePassword == password) {
                return true;
            }
        }
    }
    return false;
}

// Function to create a new user account
void CreateAccount(const std::string& username, const std::string& password) {
    std::ofstream file("accounts.txt", std::ios_base::app);
    file << username << ":" << password << std::endl;
}

int main() {
std::cout << R"(


      __   __     _  _ _  __     __            _  _ _   __  ___ 
     / _/  /  _]   /  ]|  |  ||    \   /  _]          /  ]|  |  | /    ||      |
    (   \_  /  [_   /  / |  |  ||  D  ) /  [_  ___   /  / |  |  ||  o  ||      |
     \_  ||    _] /  /  |  |  ||    / |    _]|     | /  /  |  _  ||     |||  |_|
     /  \ ||   [_ /   \_ |  :  ||    \ |   [_ |__|/   \ |  |  ||  _  |  |  |  
     \    ||     |\     ||     ||  .  \|     |       \     ||  |  ||  |  |  |  |  
      \_||__| \_| \_,||_|\||__|        \_||_|||||  |_|  
                                                                              

    )" << std::endl;
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

    // Accept incoming connection
    if ((clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen)) < 0) {
        std::cerr << "Accept failed" << std::endl;
        return 1;
    }

    std::cout << "Client connected" << std::endl;

    char buffer[BUFFER_SIZE];
    while (true) {
        // Wait for message from client
        memset(buffer, 0, sizeof(buffer));
        if (recv(clientSocket, buffer, BUFFER_SIZE, 0) <= 0) {
            std::cout << "Connection closed by client." << std::endl;
            break;
        }

        std::cout << "Client message: " << buffer << std::endl;

        // Check if the received message is a login command or create account command
        if (strncmp(buffer, "LOGIN:", 6) == 0) {
            // Extract username and password from the message
            std::string loginInfo = buffer + 6; // Skip "LOGIN:"
            size_t delimiterPos = loginInfo.find(':');
            if (delimiterPos != std::string::npos) {
                std::string username = loginInfo.substr(0, delimiterPos);
                std::string password = loginInfo.substr(delimiterPos + 1);

                // Authenticate user credentials
                if (AuthenticateUser(username, password)) {
                    send(clientSocket, "Authenticated", 14, 0);
                    std::cout << "Authentication successful" << std::endl;
                } else {
                    send(clientSocket, "Authentication failed", 21, 0);
                    std::cout << "Authentication failed" << std::endl;
                }
            }
        } else if (strncmp(buffer, "CREATE:", 7) == 0) {
            // Extract username and password from the message
            std::string userInfo = buffer + 7; // Skip "CREATE:"
            size_t delimiterPos = userInfo.find(':');
            if (delimiterPos != std::string::npos) {
                std::string username = userInfo.substr(0, delimiterPos);
                std::string password = userInfo.substr(delimiterPos + 1);

                // Create new user account
                CreateAccount(username, password);
                send(clientSocket, "Account created", 16, 0);
                std::cout << "New account created: " << username << std::endl;
            }
        } else {
            // Assume received message is a chat message
            std::cout << "Client: " << buffer << std::endl;

            // Prompt server operator for custom message
            std::string serverMessage;
            std::cout << "Server: Enter response message: ";
            std::getline(std::cin, serverMessage);

            // Send the custom message back to the client
            send(clientSocket, serverMessage.c_str(), serverMessage.size(), 0);
        }
    }

    close(clientSocket);
    close(serverSocket);

    return 0;
}

