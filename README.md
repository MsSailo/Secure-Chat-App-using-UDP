# Secure-Chat-App-using-UDP

This is a C++ implementation of a secure chat application using Datagram Transport Layer Security (DTLS). 
The chat application supports both client and server modes.

To compile the code, c++ compiler like g++ is needed.

Group Members
1. Akshat Gupta : cs23mtech11001
2. Ashutosh Rajput : cs23mtech11005
3. Malsawmsanga Sailo : cs23mtech11010


-------------------------------Part 2---------------------------------

Compilation

    Command to compile the code: " g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app "

Server Mode

    Use the following command to run the application in server mode: " ./secure_chat_app -s "
    After running the application, it would start listening for clients.

Client Mode

    Use the following command to run the application in server mode: " ./secure_chat_app -c <server_hostname> "
    Replace <server_hostname> with the hostname or IP address of the server.

Security

    To secure communication between client and server (peer to peer) using UDP, Datagram Transport Layer Security (DTLS) is used.  
    Cipher suites with Perfect Forward Secrecy (PFS) are preferred to increase security.
    Certificates and keys are used to authenticate and encrypt the message received.


-------------------------------Part 3---------------------------------
Compilation : Command to compile the code: " g++ NOT_secure_chat_app.cpp -lssl -lcrypto -o NOT_secure_chat_app "

Server Mode

    Compilation : Command to compile the code: " g++ NOT_secure_chat_app.cpp -lssl -lcrypto -o NOT_secure_chat_app "
    Use the following command to run the application in server mode: " ./NOT_secure_chat_app -s "
    After running the application, it would start listening for clients.

Client Mode

    Compilation : Command to compile the code: " g++ NOT_secure_chat_app.cpp -lssl -lcrypto -o NOT_secure_chat_app "
    Use the following command to run the application in server mode: " ./NOT_secure_chat_app -c <server_hostname> "
    Replace <server_hostname> with the hostname or IP address of the server.
    
Trudy Mode

    Compilation : Command to compile the code: " g++ secure_chat_interceptor.cpp -lssl -lcrypto -o secure_chat_interceptor "
    Use the following command to run the application in server mode: " ./secure_chat_interceptor -d <client_hostname> <server_hostname>"
    Replace <client_hostname> and <server_hostname> with the hostname or IP address of the client and server.

Security

    To secure communication between client and server (peer to peer) using UDP, Datagram Transport Layer Security (DTLS) is used.  
    Cipher suites with Perfect Forward Secrecy (PFS) are preferred to increase security.
    Certificates and keys are used to authenticate and encrypt the message received.
    
-------------------------------Part 4---------------------------------
Compilation : Command to compile the code: " g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app "

Server Mode

    Compilation : Command to compile the code: " g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app "
    Use the following command to run the application in server mode: " ./secure_chat_app -s "
    After running the application, it would start listening for clients.

Client Mode

    Compilation : Command to compile the code: " g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app "
    Use the following command to run the application in server mode: " ./secure_chat_app -c <server_hostname> "
    Replace <server_hostname> with the hostname or IP address of the server.
    
Trudy Mode

    Compilation : Command to compile the code: " g++ secure_chat_interceptor_active.cpp -lssl -lcrypto -o secure_chat_interceptor_active "
    Use the following command to run the application in server mode: " ./secure_chat_interceptor_active -m <client_hostname> <server_hostname>"
    Replace <client_hostname> and <server_hostname> with the hostname or IP address of the client and server.

Security

    To secure communication between client and server (peer to peer) using UDP, Datagram Transport Layer Security (DTLS) is used.  
    Cipher suites with Perfect Forward Secrecy (PFS) are preferred to increase security.
    Certificates and keys are used to authenticate and encrypt the message received.
