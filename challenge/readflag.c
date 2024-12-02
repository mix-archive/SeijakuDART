#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int main(void)
{
    if (setuid(0) < 0)
    {
        perror("setuid");
        return 1;
    }

    char flag[256] = {0};
    FILE *fp = fopen("/flag", "r");
    if (!fp)
    {
        perror("fopen");
        return 1;
    }

    fread(flag, sizeof(char), sizeof(flag), fp);
    puts(flag);
    fclose(fp);

    return 0;
}