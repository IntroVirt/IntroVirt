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

#include <iostream>

using namespace std;
using namespace introvirt;

int main(int argc, char** argv) {
    try {
        auto hypervisor = Hypervisor::instance();
        if (argc < 2) {
            cerr << "Usage: " << argv[0] << " <domain id>\n";
            return 1;
        }

        std::unique_ptr<Domain> d = hypervisor->attach_domain(argv[1]);

        const uint64_t pfns = 1;
        auto mapping = d->map_pfns(&pfns, 1);
        HexDump(mapping.get(), 4096, 0).write();
    } catch (TraceableException& ex) {
        std::cout << ex;
    }
}
