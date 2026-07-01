#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
static long raw6(long n,long a0,long a1,long a2,long a3,long a4,long a5){
  register long x16 asm("x16")=n;
  register long x0 asm("x0")=a0; register long x1 asm("x1")=a1;
  register long x2 asm("x2")=a2; register long x3 asm("x3")=a3;
  register long x4 asm("x4")=a4; register long x5 asm("x5")=a5;
  asm volatile("svc #0x80":"+r"(x0):"r"(x16),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"cc","memory");
  return x0;
}
