#ifndef PRIVATE_GREATER_THAN_PPDT_HPP
#define PRIVATE_GREATER_THAN_PPDT_HPP
#include <boost/asio/ip/tcp.hpp>
#include "network/net_io.hpp"
#include <string>
#include <memory>
using boost::asio::ip::tcp;

class PPDTServer {
public:
    PPDTServer() {}

    ~PPDTServer() {}

    bool load(std::string const& file);

    void run(tcp::iostream &conn) ;

private:
    struct Imp;
    std::shared_ptr<Imp> imp_;
};

class PPDTClient {
public:
    PPDTClient() {}

    ~PPDTClient() {}

    bool load(std::string const& file);

    void run(tcp::iostream &conn);

private:
    struct Imp;
    std::shared_ptr<Imp> imp_;
};
#endif
