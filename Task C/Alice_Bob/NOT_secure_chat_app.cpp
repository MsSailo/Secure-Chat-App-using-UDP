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
int sockfd, connfd;
struct sockaddr_in addr;
struct timeval timeout;
socklen_t addr_len = sizeof(addr);
char buff[MAX];
bool workAsClient;
bool downgradeClient = false;
bool downgradeServer = true;
SSL_CTX *ssl_context;
SSL *ssl;
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

void fillBuffer(char *buff, string s)
{
    bzero(buff, sizeof(buff));
    int i = 0, msgLen = s.length();

    for (int x = 0; x < msgLen; x++)
        buff[i++] = s[x];
    buff[msgLen] = '\0';
}

void fillBuffer(char *buff)
{
    bzero(buff, sizeof(buff));
    int i = 0;
    while ((buff[i++] = getchar()) != '\n')
        ;
}

void sendMessage(string s)
{
    fillBuffer(buff, s);

    sendto(sockfd, (const char *)buff, strlen(buff), MSG_CONFIRM, (const struct sockaddr *)&addr, addr_len);
}

string recvMessage(bool printit)
{
    bzero(buff, sizeof(buff));
    int n = recvfrom(sockfd, (char *)buff, MAX, MSG_WAITALL, (struct sockaddr *)&addr, &addr_len);
    buff[n] = '\0';

    if (printit == true)
    {
        if (workAsClient)
        {
            cout << "Message received from server: " << buff << "\n";
        }
        else
        {
            cout << "Message received from client: " << buff << "\n";
        }
    }

    string ret;
    int i = 0;

    while (buff[i] != '\0')
        ret += buff[i++];

    ret[n] = '\0';

    if (ret == "chat_START_SSL_NOT_SUPPORTED")
    {
        downgradeClient = true;
    }
    if (ret == "chat_START_SSL")
    {
        downgradeServer = false;
    }

    return ret;
}

string SSL_r()
{
    char buffer[MAX];
    int bytes;

    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0)
    {
        ERR_print_errors_fp(stderr);
        return "";
    }
    buffer[bytes] = '\0';
    return string(buffer);
}

void SSL_w(const std::string &message)
{
    fillBuffer(buff, message);
    SSL_write(ssl, buff, strlen(buff));
}

void loadCertificates()
{
    const char *certificate;
    const char *privateKey;
    const char *chain;
    const char *CAfile = "CAfile.pem";

    if (workAsClient == true)
    {
        certificate = "alice_crt.pem";
        privateKey = "alice_private_key.pem";
        // chain = "alice_chain.pem";
    }
    else
    {
        certificate = "bob_crt.pem";
        privateKey = "bob_private_key.pem";
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

void initializeOpenSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();

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

    SSL_CTX_set_mode(ssl_context, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(ssl_context, (const unsigned char *)"DTLS", strlen("DTLS"));
    SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, NULL);

    if (workAsClient == false)
    {
        SSL_CTX_set_cookie_generate_cb(ssl_context, generateCookie);
        SSL_CTX_set_cookie_verify_cb(ssl_context, &verifyCookie);
    }

    loadCertificates();

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if (workAsClient == false)
    {
        bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if (!bio)
        {
            cout << "Error in creating bio";
            exit(0);
        }
    }
}

void SSL_handshake()
{
    // Now doing handshake
    ssl = SSL_new(ssl_context);

    if (workAsClient == true)
        SSL_set_fd(ssl, sockfd);

    if (workAsClient == false)
    {
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        SSL_set_bio(ssl, bio, bio);
    }

    if (workAsClient == true)
    {
        int res = SSL_connect(ssl);

        if (res <= 0)
        {
            ERR_print_errors_fp(stderr);

            int error = SSL_get_error(ssl, res);
            cerr << "Error in SSL_connect! \n  --";

            exit(EXIT_FAILURE);
        }
    }
    else
    {
        int res = 0;
        while (res <= 0)
        {
            res = DTLSv1_listen(ssl, (BIO_ADDR *)&addr);
            if (res < 0)
            {
                cout << "Error in connecting to Client";
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        }

        SSL_SESSION *session = SSL_get_session(ssl);
        SSL_accept(ssl);
    }
}

void server_func()
{
    workAsClient = false;
    cout << "\nSERVER SIDE...\n\n";
    struct sockaddr_in server_addr;

    bzero(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    socklen_t server_addr_len = sizeof(server_addr);

    if (bind(sockfd, (SA *)&server_addr, server_addr_len) != 0)
    {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Server Listening on PORT : %d\n\n", DEFAULT_PORT);

    // Processing Initial Message
    recvMessage(true);
    cout << "Message send from server: chat_reply_ok" << endl;
    sendMessage("chat_reply_ok");

    recvMessage(true);

    if (downgradeServer == true)
    {
        bool loop = true;
        while (loop == true)
        {
            cout << "Enter your message : ";
            string userInput;
            getline(cin, userInput);

            while (userInput == "")
                ;

            sendMessage(userInput);
            if (userInput == "chat_close")
            {
                cout << "Closing connection...\n\n";
                break;
            }

            string clientMessage = recvMessage(true);
            // cout << "\nClient Message : " << clientMessage << endl;

            if (clientMessage == "chat_close")
            {
                cout << "Clients Wants to close connection!\n\nClosing Connection...";
                break;
            }
        }
    }
    else
    {
        cout << "Message send from server: chat_START_SSL_ACK" << endl;
        sendMessage("chat_START_SSL_ACK");

        // Initializing OpenSSL
        cout << "\nInitializing Openssl... \n";
        initializeOpenSSL();
        cout << "OpenSSL initialized! Succeesfully!!! \n\n";

        // Doing Handshake
        cout << "Doing DTLS handshake... \n";
        SSL_handshake();
        cout << "DTLS connection established!!!!  \n\n";

        if (SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
            cout << "Client Certificate Verified!!! \n";

        bool loop = true;
        while (loop == true)
        {
            string clientMessage = SSL_r();

            if (clientMessage == "")
                continue;
            cout << "\nClient Message : " << clientMessage << endl;

            if (clientMessage == "chat_close")
            {
                cout << "Client Wants to close connection!\n\nClosing Connection...";
                break;
            }

            cout << "Enter your message : ";
            string userInput;
            getline(cin, userInput);

            SSL_w(userInput);
            if (userInput == "chat_close")
            {
                cout << "closing conection...\n";
                break;
            }
        }
    }
    cout << "\n \nConnection Closed!\n";
}

void client_func(const char *IP)
{
    workAsClient = true;
    cout << "\nCLIENT SIDE...\n\n";

    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_PORT);
    struct hostent *host_info = gethostbyname(IP);
    bcopy((char *)host_info->h_addr, (char *)&addr.sin_addr.s_addr, host_info->h_length);

    // Connect Socket
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)))
    {
        cout << " Error in connecting socket from client";
        exit(0);
    }

    // Processing Initial Messages
    cout << "Message send from client: chat_hello" << endl;
    sendMessage("chat_hello");
    recvMessage(true);

    cout << "Message send from client: chat_START_SSL" << endl;
    sendMessage("chat_START_SSL");
    recvMessage(true);

    if (downgradeClient)
    {
        bool loop = true;
        while (loop == true)
        {
            cout << "Enter your message : ";
            string userInput;

            getline(cin, userInput);

            while (userInput == "")
                ;

            sendMessage(userInput);
            if (userInput == "chat_close")
            {
                cout << "Closing connection... \n";
                break;
            }

            string serverResponse = recvMessage(true);
            // cout << "\nServer Response : " << serverResponse << endl;

            if (serverResponse == "chat_close")
            {
                cout << "Server Wants to close connection!\n\nClosing Connection...\n";
                break;
            }
        }
    }
    else
    {
        // Initializing OpenSSL
        cout << "\nInitializing Openssl... \n";
        initializeOpenSSL();
        cout << "OpenSSL initialized! Succeesfully! \n\n";

        // Doing Handshake
        SSL_handshake();
        cout << "DTLS connection established!\n";

        if (SSL_session_reused(ssl))
        {
            cout << "Session Resumed!\n";
        }
        else
        {
            cout << "New Session Established!\n";
        }

        if (SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
            cout << "Certificate Verified! \n";

        bool loop = true;
        while (loop == true)
        {
            cout << "Enter your message : ";
            string userInput;

            getline(cin, userInput);

            while (userInput == "")
                ;

            SSL_w(userInput);
            if (userInput == "chat_close")
            {
                cout << "Closing connection... \n";
                break;
            }

            string serverResponse = SSL_r();
            cout << " \nServer Response : " << serverResponse << endl;

            if (serverResponse == "chat_close")
            {
                cout << "Server Wants to close connection!\n\nClosing Connection...\n";
                break;
            }
        }
    }
    cout << "\nConnection Closed!!\n";
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Enter at least 2 arguments.\n");
        return 1;
    }
    else if (!(strcmp(argv[1], "-c")) && argc != 3)
    {
        printf("Client requires 3 arguments.\n%s\t-c\t<IP address>\n", argv[0]);
        return 1;
    }
    else if (!(strcmp(argv[1], "-s")) && argc != 2)
    {
        printf("Server requires 2 arguments.\n%s\t-s\n", argv[0]);
        return 1;
    }
    else if ((strcmp(argv[1], "-s")) && (strcmp(argv[1], "-c")))
    {
        printf("Invalid option.\n");
        return 1;
    }
    else
    {
        // initializing socket

        cout << "\n++++++STARTING SECURE CHAT APPLCATION++++++\n\n";
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        if (sockfd < 0)
        {
            printf("socket creation failed...\n");
            exit(0);
        }
        else
            printf("Socket successfully created!!!\n");

        bzero(&addr, sizeof(addr));

        if (!(strcmp(argv[1], "-s")))
            server_func();
        else if (!(strcmp(argv[1], "-c")))
            client_func(argv[2]);
    }

    return 0;
}

