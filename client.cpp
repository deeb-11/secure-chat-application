#include <iostream>
#include <fstream>
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

   _____                                         _____  _             _
  / ____|                                       / ____|| |           | |
 | (___    ___   ___  _   _  _ __  ___  ______ | |     | |__    __ _ | |_
  \___ \  / _ \ / __|| | | || '__|/ _ \|______|| |     | '_ \  / _` || __|
  ____) ||  __/| (__ | |_| || |  |  __/        | |____ | | | || (_| || |_
 |_____/  \___| \___| \__,_||_|   \___|         \_____||_| |_| \__,_| \__|


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

    // Open file in append mode
    std::ofstream outputFile("chats.txt", std::ios_base::app);

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
            std::string encryptedMessage(buffer);
            std::string decryptedMessage = decrypt(encryptedMessage, 3); // Decrypt with Caesar cipher key = 3
            std::cout << "Server: " << decryptedMessage << std::endl;

            // Encrypt the received server message before storing in the file
            std::string encryptedServerMessage = encrypt(decryptedMessage, 3); // Encrypt with Caesar cipher key = 3

            // Save the received and encrypted message to file
            outputFile << "Server: " << encryptedServerMessage << std::endl;
        }
    }

    close(clientSocket);
    return 0;
}

