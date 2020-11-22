#ifndef __KVM_X86_KTCP_H
#define __KVM_X86_KTCP_H
/*
 * Copyright (C) 2019, Trusted Cloud Group, Shanghai Jiao Tong University.
 *
 * Authors:
 *   Yubin Chen <binsschen@sjtu.edu.cn>
 *   Zhuocheng Ding <tcbbd@sjtu.edu.cn>
 *   Jin Zhang <jzhang3002@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kernel.h>
#include <net/sock.h>

#define SUCCESS 0
// How many requests can be buffered in the listening queue
#define DEFAULT_BACKLOG 16

typedef uint32_t extent_t;

int ktcp_send(struct socket *sock, const char *buffer, size_t length,
		unsigned long flags, extent_t extent);

int ktcp_receive(struct socket *sock, char *buffer, unsigned long flags,
		extent_t *extent);

int ktcp_connect(const char *host, const char *port, struct socket **conn_socket);

int ktcp_listen(const char *host, const char *port, struct socket **listen_socket);

int ktcp_accept(struct socket *listen_socket, struct socket **accept_socket, unsigned long flags);

int ktcp_release(struct socket *conn_socket);

#endif /* __KVM_X86_KTCP_H */
