// Standalone CLI forwarding fixture; no ns-3 topology or telemetry.
#include <iostream>
int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) std::cout << argv[i] << "\n";
  return 0;
}
