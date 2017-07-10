int main()  {
    int a = 0;
    int b = 123123;
    int addr = &b;
    addr ^= a;
    a ^= addr;
    addr ^= a;
    printf("Please Input (int) : ");
    scanf("%d", a);
    printf("\n\nYour Input (int) : %d\n\n", b);
}
