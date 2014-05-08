#ifndef PACKETPEEPER_ASYNC_HPP
#define PACKETPEEPER_ASYNC_HPP

#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

namespace peep
{
    class async;

    namespace detail
    {
        struct async_func_queue {
            typedef std::mutex mutex_type;
            typedef std::condition_variable condition_variable_type;
            typedef std::function<void()> callback_type;

            async_func_queue()
            :
                quit_(false)
            {
            }

            async_func_queue(const async_func_queue&) = delete;

            mutex_type mutex_;
            condition_variable_type cv_;
            bool quit_;
            std::deque<callback_type> callbacks_;
        };
    }
}

// Not using std::async because I want to limit the number of threads spawned
// which AFAIK you can't do with std::async.
class peep::async
{
private:
    typedef detail::async_func_queue::mutex_type mutex_type;
    typedef std::thread thread_type;

public:
    explicit async(std::size_t num_threads = 5);
    ~async() noexcept;

    template<typename Function>
    void enqueue(const Function& function)
    {
        {
            std::lock_guard<mutex_type> lock(queue_.mutex_);
            assert(!queue_.quit_);
            queue_.callbacks_.push_back(function);
        }
        queue_.cv_.notify_one();
    }

    detail::async_func_queue queue_;
    std::vector<thread_type> workers_;
};

#endif

