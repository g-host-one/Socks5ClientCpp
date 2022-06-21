
#if _WIN32
    #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #pragma comment(lib, "Ws2_32.lib")
    #include <winsock2.h>
    #define socklen_t int
#elif __linux__
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    typedef int                 BOOL;
    typedef const char*         LPCSTR;
    typedef int                 SOCKET;
    typedef sockaddr_in         SOCKADDR_IN;
    typedef sockaddr            SOCKADDR;
    typedef struct hostent      HOSTENT;
    #ifndef FALSE
        #define FALSE               0
    #endif
    #ifndef TRUE
        #define TRUE                1
    #endif

#endif


#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libcrypto_static.lib")
#pragma comment(lib, "libssl_static.lib")
   

using namespace std;



class CTSocket
{
public:
    virtual BOOL CreateSocket();
    virtual BOOL Connect(unsigned long ip, unsigned short port);
    virtual BOOL Connect(LPCSTR name, unsigned short port);
    virtual int Send(const char* str, int len);
    virtual int Recv(char* buf, int max);
    virtual void Close();
    virtual unsigned long GetHost();
    SOCKET sock;

    
};

BOOL CTSocket::CreateSocket()
{
    return (sock = socket(AF_INET, SOCK_STREAM, 0)) != NULL;
}

BOOL CTSocket::Connect(unsigned long ip, unsigned short port)
{
    SOCKADDR_IN addr;
    //memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    #if _WIN32
        addr.sin_addr.S_un.S_addr = ip;
    #elif __linux__
        addr.sin_addr.s_addr = ip;
    #endif
    addr.sin_port = port;
    return connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == 0;
}

BOOL CTSocket::Connect(LPCSTR name, unsigned short port)
{
    HOSTENT* p = gethostbyname(name);
    if (p == NULL) return FALSE;
    return Connect(p->h_addr_list[0], port);
}

int CTSocket::Send(const char* str, int len)
{
    return send(sock, str, len, 0);
}

int CTSocket::Recv(char* buf, int max)
{
    return recv(sock, buf, max, 0);
}

void CTSocket::Close()
{
  /*
#if _WIN32
    closesocket(sock);
#elif __linux__
    Close(sock);
#endif*/
    
}

unsigned long CTSocket::GetHost()
{
    SOCKADDR_IN addr;
    socklen_t cbName = sizeof(addr);
    if (getsockname(sock, (SOCKADDR*)&addr, &cbName) == 0)
    {
        #if _WIN32
                return addr.sin_addr.S_un.S_addr;
        #elif __linux__
                return addr.sin_addr.s_addr;
        #endif
    }
    else return 0;
}


class CSocksSocket : public CTSocket
{
public:
    virtual BOOL CreateSocket();
    virtual BOOL Connect(unsigned long ip, unsigned short port);
    virtual BOOL Connect(LPCSTR name, unsigned short port);
    virtual int Send(const char* str, int len);
    virtual int Recv(char* buf, int max);
    virtual void Close();
    virtual unsigned long GetHost();

    CTSocket* pSocket;
    unsigned long socks_ip;
    unsigned short socks_port;

private:
    char buffer[512];   
    unsigned long l_ip;   
};

BOOL CSocksSocket::CreateSocket()
{
    if (!pSocket->CreateSocket()) return FALSE;
    if (!pSocket->Connect(socks_ip, socks_port)) return FALSE;
    buffer[0] = 5;  // Ver
    buffer[1] = 2;  // 2 methods
    buffer[2] = 0;  // no auth
    buffer[3] = 2;  // USERNAME/PASSWORD
    pSocket->Send(buffer, 4);
    int n = pSocket->Recv(buffer, 2);
    if (n != 2) return FALSE;

    printf("Method: %x \n", buffer[1]);

    if (buffer[1] == 0) return TRUE;  // method 0 supported

    const char * username = "";
    const char * password = "";

    if (buffer[1] == 2) { // method USERNAME/PASSWORD

        buffer[0] = 1;  // Ver
        buffer[1] = strlen(username);

        memcpy((void*)(buffer + 2), (void*)username, strlen(username));

        buffer[strlen(username) + 2] = strlen(password);

        memcpy((void*)(buffer + strlen(username) + 3), (void*)password, strlen(password));

        pSocket->Send(buffer, 2 + strlen(username) + 1 + strlen(password));


        int n = pSocket->Recv(buffer, 2);

        if (n != 2) return FALSE;

        printf("Auth: %x \n", buffer[1]);

        if (buffer[1] != 0) return FALSE;

        return TRUE;
    }

    return FALSE;
}

BOOL CSocksSocket::Connect(unsigned long ip, unsigned short port)
{
    buffer[0] = 5;  // Ver
    buffer[1] = 1;  // CONNECT
    buffer[2] = 0;  // Reserved
    buffer[3] = 1;  // IPv4
    *((unsigned long*)(buffer + 4)) = ip;
    *((unsigned short*)(buffer + 8)) = port;
    pSocket->Send(buffer, 10);
    int n = pSocket->Recv(buffer, 10);
    if (n != 10) return FALSE;
    if (buffer[1] != 0) return FALSE;
    if (buffer[3] != 1) return FALSE;
    l_ip = *((unsigned long*)(buffer + 4));
    return TRUE;
}

BOOL CSocksSocket::Connect(LPCSTR name, unsigned short port)
{
    buffer[0] = 5;
    buffer[1] = 1;
    buffer[2] = 0;
    buffer[3] = 3;
    int m = strlen(name);
    buffer[4] = m;
    memcpy(buffer + 5, name, m);
    *((unsigned short*)(buffer + 5 + m)) = port;
    pSocket->Send(buffer, m + 7);
    int n = pSocket->Recv(buffer, 10);
    if (n != 10) return FALSE;
    if (buffer[1] != 0) return FALSE;
    if (buffer[3] != 1) return FALSE;
    l_ip = *((unsigned long*)(buffer + 4));
    return TRUE;
}

int CSocksSocket::Send(const char* str, int len)
{
    return pSocket->Send(str, len);
}

int CSocksSocket::Recv(char* buf, int max)
{
    return pSocket->Recv(buf, max);
}

void CSocksSocket::Close()
{
    pSocket->Close();
}

unsigned long CSocksSocket::GetHost()
{
    return l_ip;
}

char* requestHeaderBuilder() {
    return NULL;
}


int main()
{
#if _WIN32
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif

    CTSocket tsock;
    CSocksSocket ssock;
    ssock.pSocket = &tsock;

    ssock.socks_ip = inet_addr("");
    ssock.socks_port = htons(1080);

    std::cout << "OK 1";

    if (!ssock.CreateSocket()) {
        std::cout << "Can't connect to socks";
        return 4;
    }           

    std::cout << "OK 2";

    if (!ssock.Connect("whatismyipaddress.com", htons(443))) {
        std::cout << "Can't connect to host";
        return 6; 
    }                        

    std::cout << "OK 3";

    SSL* ssl;
    int sock;

    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* meth = TLSv1_2_client_method();
    SSL_CTX* ctx = SSL_CTX_new(meth);
    ssl = SSL_new(ctx);

    sock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, ssock.pSocket->sock);
    int err = SSL_connect(ssl);
    if (err <= 0) {
        printf("Error creating SSL connection.  err=%x\n", err);
        fflush(stdout);
        return -1;
    }
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    const char * q = "GET / HTTP/1.1\xD\xAHost: whatismyipaddress.com\xD\xAUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36\xD\xA\xD\xA";

    int len = SSL_write(ssl, q, strlen(q));

    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        switch (err) {
        case SSL_ERROR_WANT_WRITE:
            return 0;
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return -1;
        }
    }

    //ssock.Send(q, strlen(q));

    char buf2[65536];
    int n;
    do {
        n = SSL_read(ssl, buf2, 65536);
        buf2[n] = 0;
        printf("%s", buf2);
    } while (n > 0);
    


    //int n = ssock.Recv(buf2, 1000);
    
   
  
    ssock.Close();

#if _WIN32
    WSACleanup();
#endif
}