#include <stdio.h>
#include <string.h>

#define BUF_LEN 50

int eval( char* str ) __attribute__ ((noinline));

__attribute__ ((noinline))
int eval( char* str )
{
    int ret = 0;
    if (strlen( str ) > 4)
    if (str[2] == 'h')
    if (str[3] == 'e')
    if (str[9] == 'l')
    if (str[0] == 'o')
    if (str[6] == 'w')
    if (str[7] == 'o')
    if (str[4] == 'r')
    if (str[10] == 'd')
    if (str[1] == 't')
    if (str[8] == 'r')
    if (str[11] != 'y') {
        ret = 1;
    }

    return ret;
}

int main(int argc, char* argv[])
{
    if (argc == 2) {
        FILE *file = fopen(argv[1], "r");
        if (file != NULL) {
            char str[BUF_LEN];
            if (fgets(str, BUF_LEN, file) != NULL) {
                if (eval(str)) {
                    int y = 0;
                    for (int i = 0; i < 100; i++) y += i;
                    printf("y = %d\n", y);
                } else {
                    printf("No!\n");
                }
            }
            fclose(file);
        }
    }
    return 0;
}
