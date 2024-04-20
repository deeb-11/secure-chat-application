#include <iostream>

#include <cstring>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <unistd.h>



constexpr int PORT = 4500;

constexpr int BUFFER_SIZE = 1024;



int main() {

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



    // Prompt user to enter username and password

    std::string username, password;

    std::cout << "Enter username: ";

    std::getline(std::cin, username); // Read entire line

    std::cout << "Enter password: ";

    std::getline(std::cin, password); // Read entire line



    // Construct login command

    std::string loginCommand = "LOGIN:" + username + ":" + password;

    send(clientSocket, loginCommand.c_str(), loginCommand.size(), 0);



    char buffer[BUFFER_SIZE];

    memset(buffer, 0, sizeof(buffer));



    // Receive response from server

    if (recv(clientSocket, buffer, BUFFER_SIZE, 0) <= 0) {

        std::cout << "Connection closed by server." << std::endl;

        close(clientSocket);

        return 1;

    } else {

        std::cout << "Server response: " << buffer << std::endl;



        // If login successful, enter chat loop

        while (true) {

            std::string message;

            std::cout << "Enter message (type 'quit' to exit): ";

            std::getline(std::cin, message); // Read entire line



            if (message == "quit") {

                break;

            }



            send(clientSocket, message.c_str(), message.size(), 0);



            memset(buffer, 0, sizeof(buffer));

            if (recv(clientSocket, buffer, BUFFER_SIZE, 0) <= 0) {

                std::cout << "Connection closed by server." << std::endl;

                break;

            } else {

                std::cout << "Server: " << buffer << std::endl;

            }

        }

    }



    close(clientSocket);



    return 0;

}

