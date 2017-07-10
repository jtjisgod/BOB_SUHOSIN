#include <stdio.h>

int main()
{
	int x[4] = { 0x12345678, 0x98765432, 0xABCDEFED, 0x12345678 };
	scanf("%d", &x[3]);
	printf("result: %d\n", (~(int)x[3] ^ (!(unsigned int)main + !(int)&x[1]) ^ (*(unsigned int *)((unsigned int)&x[2] + !x[2] + !x[0]) | x[1])));
	return 0;
}