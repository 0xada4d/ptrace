#include <stdio.h>
#include <unistd.h>

int main(void)
{
    while (1)
    {
	printf("Hello there\n");
	sleep(3);
	printf("Goodbye now\n");
	sleep(3);
    }
    return 0;
}
