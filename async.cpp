#include "async.hpp"

#include <iostream>
#include <functional>
#include <stdexcept>

namespace
{
    void worker(peep::detail::async_func_queue& queue)
    {
        std::unique_lock<peep::detail::async_func_queue::mutex_type> lock(queue.mutex_);
        while (!queue.quit_)
        {
            while (!queue.callbacks_.empty())
            {
                const peep::detail::async_func_queue::callback_type callback =
                    queue.callbacks_.front();
                queue.callbacks_.pop_front();
                lock.unlock();
                try
                {
                    callback();
                }
                catch (const std::exception& e)
                {
                    std::cerr << "peep::async: Callback error: " << e.what() << "\n";
                }
                catch (...)
                {
                    std::cerr << "peep::async: Callback error: unknown exception\n";
                }
                lock.lock();
            }
            // might have been signalled to quit while invoking callbacks
            if (queue.quit_)
                break;
            queue.cv_.wait(lock);
        }
    }
}

peep::async::async(std::size_t num_threads)
{
    workers_.reserve(num_threads);
    for (std::size_t i = 0; i < num_threads; ++i)
        workers_.push_back(std::thread(worker, std::ref(queue_)));
}

peep::async::~async() noexcept
{
    {
        std::lock_guard<mutex_type> lock(queue_.mutex_);
        assert(!queue_.quit_);
        queue_.quit_ = true;
    }
    queue_.cv_.notify_all();
    for (auto it = workers_.begin() ; it != workers_.end(); ++it)
        it->join();
}

