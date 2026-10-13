#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 3) return 64;
  char byte;
  int input = open(argv[1], O_RDONLY);
  if (input < 0) return 2;
  int read_ok = read(input, &byte, 1) == 1;
  close(input);
  if (!read_ok) return 3;
  int output = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (output < 0) return 4;
  int write_ok = write(output, &byte, 1) == 1;
  close(output);
  return write_ok ? 0 : 5;
}
