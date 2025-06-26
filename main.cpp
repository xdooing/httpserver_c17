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
#include <type_traits>
#include <deque>
#include <sys/epoll.h>

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

#define STRINGIZE(x) #x
#define SOURCE_INFO_IMPL(file, line) "In " file ":" STRINGIZE(line) ": "
#define SOURCE_INFO() SOURCE_INFO_IMPL(__FILE__, __LINE__)
#define CHECK_CALL_EXCEPT(except, func, ...) check_error<except>(SOURCE_INFO() #func, func(__VA_ARGS__))
#define CHECK_CALL(func, ...) check_error(SOURCE_INFO() #func, func(__VA_ARGS__))


struct address_resolver {
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

    bytes_const_view() noexcept : data_(nullptr), size_(0) {}
    bytes_const_view(const char* data, size_t size) noexcept 
        : data_(data), size_(size) {}
    explicit bytes_const_view(const std::string& s) noexcept 
        : data_(s.data()), size_(s.size()) {}
    // 添加接受 std::string_view 的构造函数（可以是非 explicit 的，以实现隐式转换）
    bytes_const_view(std::string_view sv) noexcept 
        : data_(sv.data()), size_(sv.size()) {}

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

    bytes_const_view subspan(size_t start,
                             size_t len = static_cast<size_t>(-1)) const {
        if (start > size()) {
            throw std::out_of_range("bytes_const_view::subspan");
        }
        if (len > size() - start) {
            len = size() - start;
        }
        return {data() + start, len};
    }

    operator std::string_view() const noexcept {
        return std::string_view{data(), size()};
    }
};

struct bytes_view {
    char* data_;
    size_t size_;

    bytes_view(std::string sv) noexcept 
        : data_(sv.data()), size_(sv.size()) {}
    bytes_view(std::string_view sv) noexcept 
        : data_(const_cast<char*>(sv.data())), size_(sv.size()) {}
    
    bytes_view(char* data, size_t size) noexcept
        : data_(data), size_(size) {}

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

    bytes_view subspan(size_t start, size_t len) const {
        if (start > size()) {
            throw std::out_of_range("bytes_view::subspan");
        }
        if (len > size() - start) {
            len = size() - start;
        }
        return bytes_view(data() + start, len);
    }

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

    bytes_const_view subspan(size_t start, size_t len) const {
        return operator bytes_const_view().subspan(start, len);
    }

    bytes_view subspan(size_t start, size_t len) {
        return operator bytes_view().subspan(start, len);
    }

    operator bytes_const_view() const noexcept {
        return bytes_const_view{data_.data(), data_.size()};
    }
    operator bytes_view() noexcept {
        return bytes_view{data_.data(), data_.size()};
    }
    operator std::string_view() const noexcept {
        return std::string_view{data_.data(), data_.size()};
    }
    operator std::string() const noexcept {
        return std::string(data_.begin(), data_.end());
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

    void reset_state() {
        header_.clear();
        headline_.clear();
        header_keys_.clear();
        body_.clear();
        head_finished_ = false;
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

    void reset_state() {
        header_parser.reset_state();
        content_length = 0;
        body_accumulated_size = 0;
        body_finish = false;
    }

    bool header_finished() {
        return header_parser.head_finished();
    }

    bool request_finished() {
        return body_finish; // 正文结束了，不需要其他数据了
    }
    std::string header_raw() {
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

// TODO: 万能引用 完美转发 引用折叠
template <class... Args>
struct callback {
    struct _callback_base{
        virtual void _call(Args... args) = 0;
        virtual ~_callback_base() = default;
    };

    // final: 禁止继承
    template <class F>
    struct _callback_impl final : _callback_base {
        F func_;
        template <class... Ts, class = std::enable_if_t<std::is_constructible_v<F, Ts...>>>
        _callback_impl(Ts&&... ts) : func_(std::forward<Ts>(ts)...) { }

        void _call(Args... args) override {
            func_(std::forward<Args>(args)...);
        }
    };

    std::unique_ptr<_callback_base> base_;

    template <class F, class = std::enable_if_t<std::is_invocable_v<F, Args...> && !std::is_same_v<std::decay_t<F>, callback>>>
    callback(F&& f) : base_(std::make_unique<_callback_impl<std::decay_t<F>>>(std::forward<F>(f))) { }

    callback() = default;
    callback(callback&&) = default;
    callback& operator=(callback&&) = default;
    callback(const callback&) = delete;
    callback& operator=(const callback&) = delete;

    void operator()(Args... args) {
        assert(base_);
        base_->_call(std::forward<Args>(args)...);
        base_ = nullptr; // 所有回调，只能调用一次
    }

    // TODO
    // void operator()(multishot_call_t, Args... args) const {
    //     assert(m_base);
    //     m_base->_call(std::forward<Args>(args)...);
    // }

    void* get_address() const noexcept {
        return static_cast<void *>(base_.get());
    }

    void* leak_address() noexcept {
        return static_cast<void *>(base_.release());
    }

    // static callback from_address(void *addr) noexcept {
    //     callback cb;
    //     cb.m_base = std::unique_ptr<_callback_base>(
    //         static_cast<_callback_base *>(addr));
    //     return cb;
    // }

    explicit operator bool() const noexcept {
        return base_ != nullptr;
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

// epoll
int epollfd;
// 异步
std::deque<callback<>> to_be_called_later;

struct async_file {
    int fd_;

    static async_file async_wrap(int fd) {
        int flags = CHECK_CALL(fcntl, fd, F_GETFL);
        // 将文件描述符设置为非阻塞
        flags |= O_NONBLOCK;
        CHECK_CALL(fcntl, fd, F_SETFL, flags);

        // create epoll
        struct epoll_event event;
        event.events = EPOLLIN | EPOLLET;
        epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);

        return async_file{fd};
    }
    // 阻塞read
    ssize_t sync_read(bytes_view buf) {
        // 这里相当于用while循环模拟了一下阻塞read，毕竟fd已经被置为了非阻塞，直接用read的话可能会返回EAGAIN
        ssize_t ret;
        do {
            ret = CHECK_CALL_EXCEPT(EAGAIN, read, fd_, buf.data(), buf.size());
        } while (ret == -1);
        return ret;
    }
    
    // 非阻塞read
    void async_read(bytes_view buf, callback<ssize_t> cb) {
        ssize_t ret = CHECK_CALL_EXCEPT(EAGAIN, read, fd_, buf.data(), buf.size());
        if(ret != -1) {
            cb(ret);
            return;
        }else {
            // cb = std::move(cb) 表示移动捕获，表示将cb的所有权转移到lambda函数内
            // 外部的cb会变的无效，也就是移出状态，这被视为一种修改，因此这里需要是用 mutable
            // 当需要在 lambda 内修改按值捕获的变量时，必须使用 mutable
            to_be_called_later.push_back([this, buf, cb = std::move(cb)] () mutable {
                async_read(buf, std::move(cb));
            });
        }
    }

    ssize_t sync_write(bytes_view buf) {
        return CHECK_CALL(write, fd_, buf.data(), buf.size());
    }

    void async_write(bytes_view buf, callback<ssize_t> cb) {
        cb(CHECK_CALL(write, fd_, buf.data(), buf.size()));
    }

    void close_file() {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, fd_, NULL);
        close(fd_);
    }
};

struct http_connection_handler {
    async_file conn_;
    bytes_buffer buf_{1024};
    // 类模板参数推导是C++17才引入的特性，而类成员声明语法保持了向前兼容
    // 所以其他局部变量可以直接 http_request_parser req_parser_;
    http_request_parser<> req_parser_;

    void do_init(int connfd) {
        conn_ = async_file::async_wrap(connfd);
        // 初始化的时候就开始read，因为是非阻塞的，暂时读不到数据的话会延迟调用callback函数的
        do_read();
    }

    void do_read() {
        fmt::println("begin read...");
        // 这里的ssize_t n 看似是参数，实际上可以理解为回调函数的返回值
        conn_.async_read(buf_, [this](ssize_t n){
            if(n == 0) {
                fmt::println("CONNECTION SHUT DOWN.");
                do_close();
                return;
            }
            req_parser_.push_chunk(buf_.subspan(0, n));
            if(!req_parser_.request_finished()) {
                do_read();
            }else {
                do_write();
            }
        });
    }

    void do_write() {
        std::string body = std::move(req_parser_.body());
        req_parser_.reset_state();
        if(body.empty()) {
            body = "your request is empty";
        }else {
            body = fmt::format("your request is [{}], total {} bytes", body, body.size());
        }
        http_response_writer res_writer;
        res_writer.begin_header(200);
        res_writer.write_header("Server", "c17_http");
        res_writer.write_header("Connection", "keep-alive");
        res_writer.write_header("Content-length", std::to_string(body.size()));
        res_writer.end_header();
        auto& buffer = res_writer.buffer();
        conn_.sync_write(buffer);
        conn_.sync_write(body);

        // 继续read，因为是 keep-alive
        do_read();
    }

    void do_close() {
        conn_.close_file();
        delete this;
    }
};

void server(std::string ip, std::string port) {

    fmt::println("Listening {}:{}", ip, port);
    
    address_resolver resolver;
    auto entry = resolver.resolve(ip, port);
    int listenfd = entry.create_socket_and_bind();
    CHECK_CALL(listen, listenfd, SOMAXCONN);

    //accept
    address_resolver::socket_address_storage addr;
    int connfd = CHECK_CALL(accept, listenfd, &addr.addr, &addr.addrlen);
    fmt::println("NEW CONNECTION <{}>", connfd);

    // epoll fd
    epollfd = epoll_create1(0);
    
    // 这里用new是因为有回调，因此分配在栈上的话会自动销毁，到时候回调就找不到对象执行了
    auto conn_handler = new http_connection_handler{};
    conn_handler->do_init(connfd);

    // 轮询查看是否有新的任务未处理
    while(!to_be_called_later.empty()) {
        auto task = std::move(to_be_called_later.front());
        to_be_called_later.pop_front();
        task();
    }
    fmt::println("all tasks done.");
    close(epollfd);

}


int main() {
    std::string ip = "127.0.0.1";
    std::string port = "8080";

    try {
        server(ip, port);
    } catch(const std::exception& e) {
        fmt::println("Error: {}", e.what());
    }
    
    return 0;
}