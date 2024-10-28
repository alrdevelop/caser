#ifndef _CASERV_POSTGRE_CONENCTION_POOL_H_
#define _CASERV_POSTGRE_CONENCTION_POOL_H_

#include <array>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <pqxx/connection>
#include <pqxx/pqxx>
#include <queue>
#include <string_view>

namespace postgre {

using ConnectionPtr = std::shared_ptr<pqxx::connection>;

class ConnectionPool {
public:
  ConnectionPool(const std::string_view &connectionString, long poolSize) {
    std::lock_guard<std::mutex> lock(_mutex);
    for(auto i = 0; i < poolSize; i++) {
        _connections.emplace(std::make_shared<pqxx::connection>(connectionString.data()));
    }
  }
  ~ConnectionPool() {}
  
  ConnectionPtr GetConnection() {
    std::unique_lock<std::mutex> lock(_mutex);
    while(_connections.empty()) {
        _conditon.wait(lock);
    }

    auto result = _connections.front();
    _connections.pop();
    return  result;
  }

  void FreeConnection(ConnectionPtr con) {
    std::unique_lock<std::mutex> lock(_mutex);
    _connections.push(con);
    lock.unlock();
    _conditon.notify_one();
  }
private:
  std::queue<ConnectionPtr> _connections;
  std::mutex _mutex;
  std::condition_variable _conditon;
};

using ConnectionPoolPtr = std::shared_ptr<ConnectionPool>;

class ConnectionScope {
public:
  ConnectionScope(ConnectionPoolPtr connectionPool)  : _connectionPool(connectionPool) {
    _connection = _connectionPool->GetConnection();
  }

  ~ConnectionScope() {
    if(_connection != nullptr) {
      _connectionPool->FreeConnection(_connection);
    }
  }

  ConnectionPtr GetConnection() {
    return _connection;
  }
  
private:
  ConnectionPoolPtr _connectionPool{nullptr};
  ConnectionPtr _connection;
};
} // namespace postgre

#endif //_CASERV_POSTGRE_CONENCTION_POOL_H_