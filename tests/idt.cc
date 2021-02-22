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

#include <iomanip>
#include <iostream>

using namespace std;
using namespace introvirt;
using namespace introvirt::windows;

int main(int argc, char** argv) {
    auto hypervisor = Hypervisor::instance();
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <domain id>\n";
        return 1;
    }
    std::unique_ptr<Domain> d = hypervisor->attach_domain(argv[1]);
    d->pause();

    try {
        const Vcpu& vcpu = d->vcpu(0);
        auto idt = vcpu.interrupt_descriptor_table();
        uint count = idt->count();

        std::cout << std::hex;
        for (uint i = 0; i < count; ++i) {
            auto entry = idt->entry(i);
            if (!entry->present())
                continue;
            std::cout << "[0x" << std::setw(2) << std::left << i << "] : " << std::setw(18)
                      << entry->entry_point() << " " << to_string(static_cast<x86::Exception>(i))
                      << '\n';
        }
        std::cout << std::dec;
    } catch (TraceableException& ex) {
        std::cout << ex;
    }

    d->resume();
}
