#include <stdio.h>
#include <string.h>
#include "sha256.h"

int main(int argc, char * argv[])
{
  if(argc != 2)
  {
    printf("./%s string\n", argv[0]);
    return 0;
  }

  BYTE * hash = sha256((BYTE *) argv[1], strlen(argv[1]));
  int i;
  for(i = 0; i < 32; i++) printf("%x", hash[i]);
  printf("\n");
  free(hash);

  return 0;
}
