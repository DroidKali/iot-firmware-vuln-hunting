#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    char buf[64];
    memset(buf, 0, sizeof(buf));
    int fd = openat(AT_FDCWD, "/etc/QLTEST", O_RDONLY);
    if (fd < 0) {
        const char *e = "OPEN_FAILED\n";
        write(1, e, strlen(e));
        return 2;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) {
        const char *e = "READ_FAILED\n";
        write(1, e, strlen(e));
        return 3;
    }
    write(1, buf, (size_t)n);
    return 0;
}
