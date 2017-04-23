#include <stdio.h>
#include <string.h>

#define BUF_LEN 50

int func() __attribute__ ((noinline));
void parse(int* ) __attribute__ ((noinline));
int compare(int*, int*) __attribute__ ((noinline));

void parse(int* p) {
    int a = 0x11111;
    printf("unused a = %d", a);
    *p = 123456;
}

int compare(int* p1, int* p2) {
    return *p1 < *p2;
}

int func(int* input) {
    int ret = 0, a, b;
    a = *input;
    parse(&b);

    if (compare(&a, &b)) {
        ret = 1;
    }
out:
    return ret;
}


int main(int argc, char* argv[])
{
    int input;
    FILE *file = fopen(argv[1], "r");
    if (file != NULL) {
        fscanf(file, "%d", &input);
        fclose(file);
    }

    printf("Input address: %p\n", &input);
    int ret = func(&input);
    if (ret == 1) {
        printf("Yes!\n");
    } else {
        printf("No!\n");
    }
    return 0;
}
