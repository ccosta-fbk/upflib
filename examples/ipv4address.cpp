#include <upfnetworklib/networklib.hh>

#include <iostream>
#include <string>

using namespace UPF;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Parse IPv4 addresses and print them back one per line.\n";
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        try {
            NetworkLib::IPv4Address addr{std::string(argv[i])};
            std::cout << addr << '\n';
        } catch (std::exception &e) {
            std::cout << "*** caught exception: " << e.what() << '\n';
        }
    }

    return 0;
}
