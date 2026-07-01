#include <chrono>
#include <cstdio>
int main(){
  auto t = std::chrono::steady_clock::now().time_since_epoch().count();
  FILE* f=fopen("/tmp/r5_determinism/o_steady.txt","w");
  fprintf(f,"%lld\n",(long long)t); fclose(f);
  // contrast: system_clock uses gettimeofday/clock_gettime (hooked)
  auto s = std::chrono::system_clock::now().time_since_epoch().count();
  FILE* g=fopen("/tmp/r5_determinism/o_sysclock.txt","w");
  fprintf(g,"%lld\n",(long long)s); fclose(g);
  return 0;
}
