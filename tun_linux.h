#ifndef LIVEKADEH_TUN_LINUX_H
#define LIVEKADEH_TUN_LINUX_H

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocate a Linux TUN interface (/dev/net/tun) */
static inline int tun_alloc_linux(char *dev, size_t dev_len) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("[Error] Cannot open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (dev && *dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("[Error] ioctl(TUNSETIFF) failed");
        close(fd);
        return err;
    }

    if (dev && dev_len > 0) {
        snprintf(dev, dev_len, "%s", ifr.ifr_name);
    }

    return fd;
}

/* Configure IP address and enable kernel NAT masquerade */
static inline int tun_configure_linux(const char *dev, const char *server_ip, const char *client_ip) {
    char cmd[512];

    /* Assign IP and point-to-point peer IP */
    snprintf(cmd, sizeof(cmd), "ip addr add %s peer %s dev %s 2>/dev/null || ip addr replace %s peer %s dev %s",
             server_ip, client_ip, dev, server_ip, client_ip, dev);
    if (system(cmd) != 0) {}

    /* Bring interface UP */
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up mtu 1420", dev);
    if (system(cmd) != 0) {}

    /* Enable IPv4 forwarding in kernel */
    if (system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1") != 0) {}

    /* Add NAT rule for client subnet */
    if (system("iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -j MASQUERADE >/dev/null 2>&1 || "
               "iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -j MASQUERADE") != 0) {}

    printf("[Linux TUN] Interface %s configured: %s <-> %s (MTU 1420, NAT active)\n",
           dev, server_ip, client_ip);

    return 0;
}
#endif

#endif /* LIVEKADEH_TUN_LINUX_H */
