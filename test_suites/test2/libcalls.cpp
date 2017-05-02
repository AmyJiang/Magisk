#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

#define LENGTH 50

int main(int argc, char* argv[])
{
    char *input = (char *) malloc(LENGTH);
    memset(input, 0, LENGTH);
    strcpy(input, argv[1]);
    printf("%s\n", input);

    int l = strlen(input);
    if (l > 10) {
      printf("%zd\n", l);
    }
    return 0;
}
