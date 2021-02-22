/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <introvirt/introvirt.hh>

using namespace introvirt;
using namespace introvirt::windows;

class SystemCallMonitor final : public EventCallback {
  public:
    void process_event(Event& event) override {
        switch (event.type()) {
        case EventType::EVENT_FAST_SYSCALL: {
            SystemCall* syscall = event.syscall().handler();
            if (unlikely(syscall == nullptr))
                break; // Shouldn't happen I believe

            if (!syscall->supported()) {
                // Handle system calls that aren't technically supported
                if (unsupported_)
                    event.syscall().hook_return(true);
                break;
            }

            if (likely(syscall->will_return())) {
                // The most common case
                event.syscall().hook_return(true);
            } else {
                if (json_)
                    write_json(event);
                else {
                    write_syscall(event);
                }
            }

            break;
        }
        case EventType::EVENT_FAST_SYSCALL_RET: {

            if (json_)
                write_json(event);
            else
                write_syscall(event);

            break;
        }
        default:
            // Some other event we don't care about
            break;
        }
    }

    SystemCallMonitor(bool flush, bool json, bool unsupported)
        : flush_(flush), json_(json), unsupported_(unsupported) {}
    ~SystemCallMonitor() { std::cout.flush(); }

  private:
    void write_syscall(const Event& event) {
        std::lock_guard lock(mtx_);

        const Vcpu& vcpu = event.vcpu();
        std::cout << "Vcpu " << vcpu.id() << ": [" << event.task().pid() << ":"
                  << event.task().tid() << "] " << event.task().process_name() << '\n';
        std::cout << event.syscall().name() << '\n';
        if (event.syscall().handler())
            event.syscall().handler()->write();
        if (flush_)
            std::cout.flush();
    }

    void write_json(const Event& event) {
        std::lock_guard lock(mtx_);
        std::cout << event.json() << '\n';
        if (flush_)
            std::cout.flush();
    }

    std::mutex mtx_;
    const bool flush_;
    const bool json_;
    const bool unsupported_;
};