#include <introvirt/introvirt.hh>

#include <iostream>

using namespace std;
using namespace introvirt;

int main(int argc, char** argv) {

    std::cout << "libintrovirt " << introvirt::VersionInfo::version();

    if (VersionInfo::is_optimized_build())
        std::cout << " Optimized";

    if (VersionInfo::is_debug_build())
        std::cout << " Debug";

    std::cout << '\n';

    try {
        auto hypervisor = Hypervisor::instance();

        std::cout << "  Hypervisor : " << hypervisor->hypervisor_name() << ' '
                  << hypervisor->hypervisor_version() << '\n';
        std::cout << "    IntroVirt Patch : " << hypervisor->hypervisor_patch_version() << '\n';
        std::cout << "    " << hypervisor->library_name() << " " << hypervisor->library_version()
                  << '\n';

    } catch (UnsupportedHypervisorException& ex) {
        std::cout << "No supported hypervisor detected\n";
        return 1;
    }

    return 0;
}
