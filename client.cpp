#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

constexpr int PORT = 4500;
constexpr int BUFFER_SIZE = 1024;

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

// Caesar cipher decryption function
std::string decrypt(const std::string& input, int key) {
    return encrypt(input, 26 - key);
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
    int clientSocket;
    sockaddr_in serverAddr;

    // Create socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return 1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return 1;
    }

    // Connect to server
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return 1;
    }

    std::cout << "Connected to server" << std::endl;

    // Prompt user to choose action
    std::cout << "Choose action: (1) Login (2) Create Account: ";
    int choice;
    std::cin >> choice;

    if (choice == 1) {
        std::cin.ignore(); // Ignore newline character left in input buffer
        std::string username, password;
        std::cout << "Enter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);

        // Encrypt credentials before sending
        username = encrypt(username, 3); // Encrypt with Caesar cipher key = 3
        password = encrypt(password, 3);

        // Construct login command
        std::string loginCommand = "LOGIN:" + username + ":" + password;
        send(clientSocket, loginCommand.c_str(), loginCommand.size(), 0);
    } else if (choice == 2) {
        std::cin.ignore(); // Ignore newline character left in input buffer
        std::string username, password;
        std::cout << "Enter new username: ";
        std::getline(std::cin, username);
        std::cout << "Enter new password: ";
        std::getline(std::cin, password);

  // Encrypt credentials before sending
        username = encrypt(username, 3); // Encrypt with Caesar cipher key = 3
        password = encrypt(password, 3);


        // Construct create account command
        std::string createCommand = "CREATE:" + username + ":" + password;
        send(clientSocket, createCommand.c_str(), createCommand.size(), 0);
    } else {
        std::cout << "Invalid choice" << std::endl;
        return 1;
    }

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    // Receive response from server
    if (recv(clientSocket, buffer, BUFFER_SIZE, 0) <= 0) {
        std::cout << "Connection closed by server." << std::endl;
        close(clientSocket);
        return 1;
    } else {
        std::cout << "Server response: " << buffer << std::endl;
    }

    // Enter chat loop
    while (true) {
        std::string message;
        std::cout << "Enter message (type 'quit' to exit): ";
        std::getline(std::cin, message);

        if (message == "quit") {
            break;
        }

        send(clientSocket, message.c_str(), message.size(), 0);

        memset(buffer, 0, sizeof(buffer));
        if (recv(clientSocket, buffer, BUFFER_SIZE, 0) <= 0) {
            std::cout << "Connection closed by server." << std::endl;
            close(clientSocket);
            return 1;
        } else {
            std::cout << "Server: " << buffer << std::endl;
        }
    }

    close(clientSocket);
    return 0;
}
