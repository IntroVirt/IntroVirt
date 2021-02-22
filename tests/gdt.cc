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

void print_header() {
    std::cout << "Sel              ";
    std::cout << "Base          ";
    std::cout << "Limit         ";
    std::cout << "Dpl     ";
    std::cout << "Type    ";
    std::cout << "Flags\n";
    std::cout
        << "----------------------------------------------------------------------------------\n";
}

void dump_segment(const x86::Segment& segment, bool ldt) {

    uint16_t selector = segment.selector().value();
    if (ldt)
        selector |= 0x4;

    std::cout << std::hex;
    std::cout << "0x" << std::setw(3) << std::setfill('0') << selector << "    ";
    std::cout << "0x" << std::setw(16) << std::setfill('0') << segment.base() << "    ";
    std::cout << "0x" << std::setw(8) << std::setfill('0') << segment.limit() << "    ";
    std::cout << "0x" << std::setw(2) << std::setfill('0')
              << (static_cast<int>(segment.dpl()) & 0xFF) << "    ";

    if (segment.s()) {

        if (segment.code()) {
            std::cout << "code";
        } else {
            std::cout << "data";
        }
        std::cout << "    [ s ";
        if (segment.granularity())
            std::cout << "g ";
        if (segment.db())
            std::cout << "db ";
        if (segment.long_mode())
            std::cout << "l ";
        if (segment.avl())
            std::cout << "avl ";

        if (segment.code()) {
            if (segment.conforming())
                std::cout << "c ";
            if (segment.readable())
                std::cout << "r ";
        } else {
            if (segment.expand_down())
                std::cout << "d ";
            if (segment.writable())
                std::cout << "w ";
        }

        if (segment.accessed())
            std::cout << "a ";

    } else {
        std::cout << "0x" << std::setw(2) << std::setfill('0')
                  << (static_cast<int>(segment.type()) & 0xFF) << "    [";
    }

    std::cout << "]" << std::endl;
    std::cout << std::dec;
}

void dump_table(const x86::SegmentDescriptorTable& table, bool ldt) {
    const int count = table.count();

    for (int i = 0; i < count; ++i) {
        dump_segment(table.index(i), ldt);
    }
}

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

        std::cout << "GDT=0x" << std::hex << vcpu.registers().gdtr_base() << " Limit=0x"
                  << vcpu.registers().gdtr_limit() << std::dec << '\n';

        print_header();
        auto gdt = vcpu.global_descriptor_table();
        dump_table(gdt, false);
        std::cout << '\n';

        std::cout << "LDT\n";
        dump_segment(vcpu.registers().ldt(), false);
        if (vcpu.registers().ldt().base()) {
            print_header();
            auto ldt = vcpu.global_descriptor_table();
            dump_table(ldt, true);
            std::cout << '\n';
        }

        std::cout << "CS\n";
        dump_segment(vcpu.registers().cs(), false);
        std::cout << "FS\n";
        dump_segment(vcpu.registers().ds(), false);
        std::cout << "ES\n";
        dump_segment(vcpu.registers().es(), false);
        std::cout << "FS\n";
        dump_segment(vcpu.registers().fs(), false);
        std::cout << "GS\n";
        dump_segment(vcpu.registers().gs(), false);
        std::cout << "SS\n";
        dump_segment(vcpu.registers().ss(), false);
        std::cout << "TR\n";
        dump_segment(vcpu.registers().tr(), false);

    } catch (TraceableException& ex) {
        std::cout << ex;
    }

    d->resume();
}
