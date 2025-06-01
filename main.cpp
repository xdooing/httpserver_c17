#include <iostream>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <fmt/format.h>
#include <thread>
#include <vector>

#if 0
struct addrinfo
{
  int ai_flags;			/* Input flags.  */
  int ai_family;		/* Protocol family for socket.  */
  int ai_socktype;		/* Socket type.  */
  int ai_protocol;		/* Protocol for socket.  */
  socklen_t ai_addrlen;		/* Length of socket address.  */
  struct sockaddr *ai_addr;	/* Socket address for socket.  */
  char *ai_canonname;		/* Canonical name for service location.  */
  struct addrinfo *ai_next;	/* Pointer to next in list.  */
};
#endif

int check_error(const char* msg, int res) {
    if(res == -1) {
        fmt::println("{}: {}", msg, strerror(errno));
        throw;
    }
    return res;
}

ssize_t check_error(const char* msg, ssize_t res) {
    if(res == -1) {
        fmt::println("{}: {}", msg, strerror(errno));
        throw;
    }
    return res;
}

#define CHECK_CALL(func, ...) check_error(#func, func(__VA_ARGS__))

struct socket_address_fatptr{
    struct sockaddr* addr;
    socklen_t addrlen;
};
struct socket_address_storage {
    union {
        struct sockaddr addr;                 // 通用地址结构
        struct sockaddr_storage addr_storage; // 足够大的存储空间（兼容 IPv4/IPv6）
    };
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    // 隐式转换为 socket_address_fatptr
    operator socket_address_fatptr() {
        return {&addr, addrlen};
    }
};

struct address_resolved_entry {
    struct addrinfo* current = nullptr;
    socket_address_fatptr get_address() const {
        return {current->ai_addr, current->ai_addrlen};
    }
    int create_socket() const {
        int socketfd = CHECK_CALL(socket, current->ai_family, current->ai_socktype, current->ai_protocol);
        return socketfd;
    }
    bool next_entry() {
        current = current->ai_next;
        return (current != nullptr);
    }

    int create_socket_and_bind() {
        int socketfd = create_socket();
        socket_address_fatptr addr = get_address();
        // bind
        CHECK_CALL(bind, socketfd, addr.addr, addr.addrlen);
        return socketfd;
    }

};

struct address_resolver {
    struct addrinfo* head = nullptr;

    address_resolver() = default;
    address_resolver(address_resolver&& that) : head(that.head) {
        that.head = nullptr;
    }
    ~address_resolver() {
        if(head)
            freeaddrinfo(head);
    }

    address_resolved_entry resolve(const std::string& name, const std::string& service) {
        int err = getaddrinfo(name.c_str(), service.c_str(), NULL, &head);
        if(err != 0) {
            fmt::println("getaddrinfo {} {}", gai_strerror(err), err);
            throw;
        }
        return {head};
    }
};

struct http_request_parser {
    std::string head;
    std::string body;
    bool head_finish = false;
    bool body_finish = false;

    bool need_more_chunks() {
        return !body_finish; // 正文结束了，不需要其他数据了
    }

    void push_chunk(std::string_view chunk) {
        if(!head_finish) {
            head.append(chunk);
            // 头部还未结束，尝试判断头部是否结束
            size_t headlen = head.find("\r\n\r\n");
            if(headlen != std::string::npos) {
                // 头部解析结束
                head_finish = true;
                // 把多余解析的body部分截取出来
                body = head.substr(headlen);
                head.resize(headlen);
                // 分析头部中的Content-Length字段
                body_finish = true;
            }
        }else {
            body.append(chunk);
        }
    }

};

std::vector<std::thread> pool;
int main() {
    std::string ip = "127.0.0.1";
    std::string port = "8080";

    fmt::println("Listening {}:{}", ip, port);
    
    address_resolver resolver;
    auto entry = resolver.resolve(ip, port);
    int listenfd = entry.create_socket_and_bind();
    CHECK_CALL(listen, listenfd, SOMAXCONN);

    //accept
    while(true) {
        socket_address_storage addr;
        int connid = CHECK_CALL(accept, listenfd, &addr.addr, &addr.addrlen);
        // handle by thread
        pool.emplace_back([connid](){
            char buf[1024];
            http_request_parser req_parser;
            do{
                ssize_t len = CHECK_CALL(read, connid, buf, sizeof(buf));
                req_parser.push_chunk(std::string_view(buf, len));
            } while (req_parser.need_more_chunks());
            
            auto req = req_parser.head;
            fmt::println("req msg: ##{}##", req);

            std::string res = "HTTP/1,1 200 OK\r\nServer: c17_http\r\nConnection: close\r\nContent-length: 5\r\n\r\nHello";
            fmt::println("res msg: ##{}##", res);
            CHECK_CALL(write, connid, res.data(), res.size());
            close(connid);
        });
    }
    for(auto& t : pool) {
        t.join();
    }
    

    return 0;
}