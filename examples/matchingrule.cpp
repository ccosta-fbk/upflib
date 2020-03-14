#include <upfdumperlib/dumper.hh>
#include <upfrouterlib/upfrouterlib.hh>

#include <iostream>
#include <string>

using namespace UPF;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Parse matching rules and print them back one per line.\n";
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        try {
            UPFRouterLib::MatchingRule rule{std::string(argv[i])};
            std::cout << rule << '\n';
        } catch (std::exception &e) {
            std::cout << "*** caught exception: " << e.what() << '\n';
        }
    }

    return 0;
}
