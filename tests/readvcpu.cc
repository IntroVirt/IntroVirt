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
    auto hypervisor = Hypervisor::instance();
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <domain id>\n";
        return 1;
    }
    std::unique_ptr<Domain> d = hypervisor->attach_domain(argv[1]);
    Vcpu& vcpu = d->vcpu(0);
    vcpu.pause();

    std::cout << "Vcpu 0: \n";

    auto& regs = vcpu.registers();

    std::cout << std::hex;
    std::cout << "  rax: 0x" << regs.rax() << '\n';
    std::cout << "  rbx: 0x" << regs.rbx() << '\n';
    std::cout << "  rcx: 0x" << regs.rcx() << '\n';
    std::cout << "  rdx: 0x" << regs.rdx() << '\n';
    std::cout << "  r8: 0x" << regs.r8() << '\n';
    std::cout << "  r9: 0x" << regs.r9() << '\n';
    std::cout << "  r10: 0x" << regs.r10() << '\n';
    std::cout << "  r11: 0x" << regs.r11() << '\n';
    std::cout << "  r12: 0x" << regs.r12() << '\n';
    std::cout << "  r13: 0x" << regs.r13() << '\n';
    std::cout << "  r14: 0x" << regs.r14() << '\n';
    std::cout << "  r15: 0x" << regs.r15() << '\n';
    std::cout << "  rsi: 0x" << regs.rsi() << '\n';
    std::cout << "  rdi: 0x" << regs.rdi() << '\n';
    std::cout << "  rsp: 0x" << regs.rsp() << '\n';
    std::cout << "  rbp: 0x" << regs.rbp() << '\n';
    std::cout << "  rip: 0x" << regs.rip() << '\n';
    std::cout << "  rflags: 0x" << regs.rflags().value() << '\n';

    std::cout << std::dec;

    vcpu.resume();
}
