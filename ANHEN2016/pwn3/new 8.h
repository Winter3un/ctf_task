#include <stdio.h>
#include <stdlib.h>


int main()
{
    int a = -2147483648 + 14;
	// char a[] = "\x12\x34\x56\x78";
    if(*((char *)&a+1) == 1)
        printf("Little-endian\n");
    else
        printf("Big-endian\n");
     return 0;
}