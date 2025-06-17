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
#include <algorithm>
#include <map>
#include <assert.h>
#include <stdio.h>
#include <functional>

void debug_msg(const char* msg) {
    return;
    FILE* g_fp = nullptr;
    std::string path = "/home/xdoo/workspace/httpserver_c17/report.log";
    g_fp = fopen(path.c_str(), "a");
    fprintf(g_fp, "%s", msg);
    fprintf(g_fp, "-----------------\n");
    if(g_fp) fclose(g_fp);
}


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

using StringMap = std::map<std::string, std::string>;

const std::error_category& gai_category() {
    static struct final : std::error_category {
        const char* name() const noexcept override {
            return "getaddrinfo";
        }
        std::string message(int err) const override {
            return gai_strerror(err);
        }
    } instance;
    // 单例模式
    return instance;
};


// 由于要进行异步的原因，系统调用返回值 == -1 的时候不一定就要抛出异常，也可以直接返回
template <int Except = 0, class T>
T check_error(const char* what, T res) {
    if(res == -1) {
        if constexpr (Except != 0) {
            if(errno == Except) {
                return -1;
            }
        }
        auto ec = std::error_code(errno, std::system_category());
        fmt::println(stderr, "{}: {}", what, ec.message());
        throw std::system_error(ec, what);
    }
    return res;
}

#define SOURCE_INFO_IMPL(file, line) "In " file ":" #line ": "
#define SOURCE_INFO() SOURCE_INFO_IMPL(__FILE__, __LINE__)
#define CHECK_CALL_EXCEPT(except, func, ...) check_error<except>(SOURCE_INFO() #func, func(__VA_ARGS__))
#define CHECK_CALL(func, ...) check_error(SOURCE_INFO() #func, func(__VA_ARGS__))

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
        // 设置端口复用
        int opt = 1;
        setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
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
            auto ec = std::error_code(err, gai_category());
            throw std::system_error(ec, name + ":" + service);;
        }
        return {head};
    }
};

struct bytes_const_view {
    const char* data_;
    size_t size_;

    const char* data() const noexcept {
        return data_;
    }
    size_t size() const noexcept {
        return size_;
    }
    const char* begin() const noexcept {
        return data();
    }
    const char* end() const noexcept {
        return data() + size();
    }

    // TODO...
    // bytes_const_view subspan

    operator std::string_view() const noexcept {
        return std::string_view{data(), size()};
    }
};

struct bytes_view {
    char* data_;
    size_t size_;

    char* data() const noexcept {
        return data_;
    }
    size_t size() const noexcept {
        return size_;
    }
    char* begin() const noexcept {
        return data();
    }
    char* end() const noexcept {
        return data() + size();
    }

    // TODO...
    // bytes_view subspan

    operator bytes_const_view() const noexcept {
        return bytes_const_view{data(), size()};
    }
    operator std::string_view() const noexcept {
        return std::string_view{data(), size()};
    }
};

struct bytes_buffer {
    std::vector<char> data_;
    bytes_buffer() = default;
    bytes_buffer(bytes_buffer&&) = default;
    bytes_buffer& operator=(bytes_buffer&&) = default;
    explicit bytes_buffer(const bytes_buffer&) = default;
    explicit bytes_buffer(size_t n) : data_(n) {}

    const char* data() const noexcept{
        return data_.data();
    }
    char* data() noexcept {
        return data_.data();
    }
    size_t size() const noexcept {
        return data_.size();
    }
    const char* begin() const noexcept {
        return data();        
    }
    char* begin() noexcept {
        return data();        
    }
    const char* end() const noexcept {
        return data() + size();        
    }
    char* end() noexcept {
        return data() + size();        
    }

    // TODO...
    // bytes_const_view subspan()
    // bytes_view subspan()

    operator bytes_const_view() const noexcept {
        return bytes_const_view{data_.data(), data_.size()};
    }
    operator bytes_view() noexcept {
        return bytes_view{data_.data(), data_.size()};
    }
    operator std::string_view() const noexcept {
        return std::string_view{data_.data(), data_.size()};
    }
    void append(bytes_const_view chunk) {
        data_.insert(data_.end(), chunk.begin(), chunk.end());
    }
    void append(std::string_view chunk) {
        data_.insert(data_.end(), chunk.begin(), chunk.end());
    }

    template <size_t N>
    void append_literial(const char (&literial)[N]) {
        append(std::string_view{literial, N - 1});
    }

    void clear() {
        data_.clear();
    }
    void resize(size_t n) {
        data_.resize(n);
    }
    void reserve(size_t n) {
        data_.reserve(n);
    }
};

template <size_t N>
struct static_bytes_buffer {
    std::array<char, N> data_;

    const char* data() const noexcept {
        return data_.data();
    }
    char* data() noexcept {
        return data_.data();
    }
    static constexpr size_t size() noexcept {
        return N;
    }
    operator bytes_const_view() const noexcept {
        return bytes_const_view{data_.data(), N};
    }
    operator bytes_view() noexcept {
        return bytes_view{data_.data(), N};
    }
    operator std::string_view() const noexcept {
        return std::string_view{data_.data(), data_.size()};
    }
};

struct http11_header_parse {
    bytes_buffer header_;      // "GET / HTTP/1.1\nHost: xdoo.log\r\nAccept: */*\r\nConnection: close"
    std::string headline_; // "GET / HTTP/1.1"
    StringMap header_keys_;
    std::string body_; // 不小心多读取的正文部分，如果有的话
    bool head_finished_ = false;

    bool head_finished() {
        return head_finished_;
    }

    void _extract_headers() {
        std::string_view header = header_;
        size_t pos = header.find("\r\n", 0, 2);
        headline_ = std::string(header.substr(0, pos));
        while(pos != std::string::npos) {
            // skip "\r\n"
            pos += 2;
            // 从当前位置开始找，先找到下一行位置（可能为npose）
            size_t next_pos = header.find("\r\n", pos, 2);
            size_t line_len = std::string::npos;
            if(next_pos != std::string::npos){
                // 如果下一行还不是结束，那么line_len设为本行开始到下一行的距离
                line_len = next_pos - pos;
            }
            // 切下本行
            std::string_view line = header.substr(pos, line_len);
            size_t colon = line.find(": ");
            if(colon != std::string::npos) {
                std::string key = std::string(line.substr(0, colon));
                std::string_view value = line.substr(colon + 2);
                // http不区分大小写，因此这里将键统一修改为小写
                std::transform(key.begin(), key.end(), key.begin(), [](char c){
                    if('A' <= c && c <= 'Z')
                        c += 'a' - 'A';
                    return c;
                });
                // c++17更高效的写法 等效于head_keys[key] = value 
                header_keys_.insert_or_assign(std::move(key), value);
            }
            pos = next_pos;
        }
    }

    void push_chunk(bytes_const_view chunk) {
        assert(!head_finished_);
        size_t old_size = header_.size();
        header_.append(chunk);
        std::string_view header_view = header_;
        // 还在解析头部的话，判断头部是否解析结束
        // "GET / HTTP/1.1\nHost: xdoo.log\r\nAccept: */*\r\nConnection: close"
        if(old_size < 4) old_size = 4;
        old_size -= 4;
        size_t head_len = header_view.find("\r\n\r\n", old_size, 4);
        if(head_len != std::string::npos) {
            // 找到'\r\n' 头部的读取结束
            head_finished_ = true;
            // 把不小心多读取的正文留下来
            body_ = header_view.substr(head_len + 4);
            header_.resize(head_len);
            // 开始分析头部，尝试提取content-length等kv键值对
            _extract_headers();
        }
    }

    std::string& headline() { 
        return headline_; 
    }
    StringMap& headers() {
        return header_keys_;
    }
    bytes_buffer& header_raw() {
        return header_;
    }
    std::string& extra_body() {
        return body_;
    }
};

template <class HeaderParser = http11_header_parse>
struct _http_base_parser {
    /*HeaderParser*/ http11_header_parse header_parser;
    size_t content_length;
    size_t body_accumulated_size = 0;
    bool body_finish = false;

    // TODO...
    // void reset_state()

    bool header_finished() {
        return header_parser.head_finished();
    }

    bool request_finished() {
        return body_finish; // 正文结束了，不需要其他数据了
    }
    std::string& header_raw() {
        return header_parser.header_raw();
    }
    std::string& headline() {
        return header_parser.headline();
    }
    StringMap& headers() {
        return header_parser.headers();
    }

    std::string _headline_first() {
        // "GET / HTTP/1.1"  --> request
        // "HTTP/1.1 200 ok" --> response
        auto& line = headline();
        size_t space = line.find(' ');
        if(space == std::string::npos){
            return "";
        }
        return line.substr(0, space);
    }

    std::string _headline_second() {
        // "GET / HTTP/1.1"
        auto& line = headline();
        size_t space1 = line.find(' ');
        if(space1 == std::string::npos){
            return "";
        }
        size_t space2 = line.find(' ', space1);
        if(space2 == std::string::npos) {
            return "";
        }
        return line.substr(space1, space2);
    }

    std::string _headline_third() {
        auto& line = headline();
        size_t space1 = line.find(' ');
        if(space1 == std::string::npos) {
            return "";
        }
        size_t space2 = line.find(' ', space1);
        if(space2 == std::string::npos) {
            return "";
        }
        return line.substr(space2);
    }

    std::string& body() {
        return header_parser.extra_body();
    }

    size_t _extract_content_length() {
        auto& headers = header_parser.headers();
        auto it = headers.find("content-length");
        if(it == headers.end()) {
            return 0;
        }
        // stoi可能会抛出异常
        try {
            return std::stoi(it->second);
        } catch(const std::logic_error&) {
            return 0;
        }
    }

    void push_chunk(bytes_const_view chunk) {
        assert(!body_finish);
        if(!header_parser.head_finished()) {
            header_parser.push_chunk(chunk);
            if(header_parser.head_finished()) {
                body_accumulated_size = body().size();
                content_length = _extract_content_length();
                // 判断正文是不是已经结束了
                if(body_accumulated_size >= content_length) {
                    body_finish = true;
                }
            }
        }else {
            body().append(chunk);
            body_accumulated_size += chunk.size();
            if(body_accumulated_size >= content_length) {
                body_finish = true;
            }
        }
    }

    // std::string read_some_body() {
    //     return std::move(body());
    // }
};

template <class HeaderParser = http11_header_parse>
struct http_request_parser : _http_base_parser<HeaderParser> {
    std::string method() {
        // "GET / HTTP/1.1"
        return this->_headline_first();
    }
    std::string url() {
        // "GET / HTTP/1.1"
        return this->_headline_second();
    }
    // std::string http_version() {
    //     // "GET / HTTP/1.1"
    //     return this->_headline_third();
    // }
};

template <class HeaderParser = http11_header_parse>
struct http_response_parser : _http_base_parser<HeaderParser> {
    // "HTTP/1.1 200 ok" --> response
    // std::string http_version() {
    //     return this->_headline_first();
    // }
    int status() {
        auto s = this->_headline_second();
        try {
            return std::stoi(s);
        } catch(const std::logic_error&) {
            return -1;
        }
    }
    // std::string status_string() {
    //     return this->_headline_third();
    // }
};

struct http11_header_writer {
    bytes_buffer buffer_;

    void reset_state() {
        buffer_.clear();
    }

    bytes_buffer& buffer() {
        return buffer_;
    }

    void begin_header(std::string_view first,
                      std::string_view second,
                      std::string_view third) {
        buffer_.append(first);
        buffer_.append_literial(" ");
        buffer_.append(second);
        buffer_.append_literial(" ");
        buffer_.append(third);
    }

    void write_header(std::string_view key, std::string_view value) {
        buffer_.append_literial("\r\n");
        buffer_.append(key);
        buffer_.append_literial(": ");
        buffer_.append(value);
    }

    void end_header() {
        buffer_.append_literial("\r\n\r\n");
    }
};

template <class HeaderWriter = http11_header_writer>
struct _http_base_writer {
    /*HeaderWriter*/ http11_header_writer header_writer_;

    void _begin_header(std::string_view first,
                       std::string_view second,
                       std::string_view third) {
        header_writer_.begin_header(first, second, third);
    }

    void reset_state() {
        header_writer_.reset_state();
    }
    bytes_buffer& buffer() {
        return header_writer_.buffer();
    }
    void write_header(std::string_view key, std::string_view value) {
        header_writer_.write_header(key, value);
    }
    void end_header() {
        header_writer_.end_header();
    }
    void write_body(std::string_view body) {
        header_writer_.buffer().append(body);
    }
};

template <class HeaderWriter = http11_header_writer>
struct http_request_writer : _http_base_writer<HeaderWriter> {
    void begin_header(std::string_view method, std::string_view url) {
        this->_begin_header(method, url, "HTTP/1.1");
    }
};

template <class HeaderWriter = http11_header_writer>
struct http_response_writer : _http_base_writer<HeaderWriter> {
    void begin_header(int status) {
        this->_begin_header("HTTP/1.1", std::to_string(status), "OK");
    }
};


std::vector<std::thread> pool;

// 异步
template <class... Args>
using callback = std::function<void(Args...)>;

struct async_file {
    int fd_;

    static async_file async_wrap(int fd) {
        int flags = CHECK_CALL(fcntl, fd, F_GETFL);
        // 将文件描述符设置为非阻塞
        flags |= O_NONBLOCK;
        CHECK_CALL(fcntl, fd, F_SETFL, flags);
        return async_file{fd};
    }
    
    ssize_t sync_read(bytes_view buf) {
        return CHECK_CALL(read, fd_, buf.data(), buf.size());
    }

    void sync_read(bytes_view buf, callback<ssize_t> cb) {
        ssize_t ret =  CHECK_CALL(read, fd_, buf.data(), buf.size());
        cb(ret);
    }

    ssize_t sync_write(bytes_view buf) {
        return CHECK_CALL(write, fd_, buf.data(), buf.size());
    }

    void sync_write(bytes_view buf, callback<ssize_t> cb) {
        ssize_t ret =  CHECK_CALL(write, fd_, buf.data(), buf.size());
        cb(ret);
    }
};

void server() {
   // TIME-> 1:24:20 
}



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
            } while (!req_parser.request_finished());
            
            fmt::println("req head: {}", req_parser.header_raw());
            fmt::println("req body: {}", req_parser.body());

            std::string res = std::string("HTTP/1.1 200 OK\r\nServer: c17_http\r\nConnection: close\r\nContent-length: ")
                            + std::to_string(req_parser.body().size()) + ("\r\n\r\n") + req_parser.body();
            fmt::println("res msg: {}", res);
            CHECK_CALL(write, connid, res.data(), res.size());
            close(connid);
        });
    }
    for(auto& t : pool) {
        t.join();
    }
    return 0;
}