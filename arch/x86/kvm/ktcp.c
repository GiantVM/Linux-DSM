/*
 * TCP support for KVM software distributed memory
 *
 * This feature allows us to run multiple KVM instances on different machines
 * sharing the same address space.
 * 
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
#include <linux/module.h>
#include <linux/init.h>

#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <linux/kvm_host.h>
#include "ktcp.h"

struct ktcp_hdr {
	extent_t extent;
	uint16_t length;
} __attribute__((packed));

#define KTCP_BUFFER_SIZE (sizeof(struct ktcp_hdr) + PAGE_SIZE)

static int __ktcp_send(struct socket *sock, const char *buffer, size_t length,
		unsigned long flags)
{
	struct kvec vec;
	int len, written = 0, left = length;
	int ret;

	struct msghdr msg = {
		.msg_name    = 0,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags   = flags,
	};

repeat_send:
	vec.iov_len = left;
	vec.iov_base = (char *)buffer + written;

	len = kernel_sendmsg(sock, &msg, &vec, 1, left);
	if (len == -EAGAIN || len == -ERESTARTSYS) {
		goto repeat_send;
	}
	if (len > 0) {
		written += len;
		left -= len;
		if (left != 0) {
			goto repeat_send;
		}
	}

	ret = written != 0 ? written : len;
	if (ret > 0 && ret != length) {
		printk(KERN_WARNING "ktcp_send send %d bytes which expected_size=%lu bytes", ret, length);
	}

	if (ret < 0) {
		printk(KERN_ERR "ktcp_send %d", ret);
	}

	return ret;
}

int ktcp_send(struct socket *sock, const char *buffer, size_t length,
		unsigned long flags, const extent_t *extent)
{
	struct ktcp_hdr hdr = {
		.length = length,
		.extent = *extent,
	};
	int ret;
	mm_segment_t oldmm;
	char *local_buffer = kmalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		return -ENOMEM;
	}

	// Get current address access limit
	oldmm = get_fs();
	set_fs(KERNEL_DS);

	memcpy(local_buffer, &hdr, sizeof(hdr));
	memcpy(local_buffer + sizeof(hdr), buffer, length);

	ret = __ktcp_send(sock, local_buffer, KTCP_BUFFER_SIZE, flags);
	if (ret < 0)
		goto out;

out:
	// Retrieve address access limit
	set_fs(oldmm);
	kfree(local_buffer);
	return ret < 0 ? ret : hdr.length;
}

static int __ktcp_receive(struct socket *sock, char *buffer, size_t expected_size,
		unsigned long flags)
{
	struct kvec vec;
	int ret;
	int len = 0;

	struct msghdr msg = {
		.msg_name    = 0,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags   = flags,
	};

	if (expected_size == 0) {
		return 0;
	}

read_again:
	vec.iov_len = expected_size - len;
	vec.iov_base = buffer + len;
	ret = kernel_recvmsg(sock, &msg, &vec, 1, expected_size - len, flags);

	if (ret == 0) {
		return len;
	}

	// Non-blocking on the first try
	if (len == 0 && (flags & SOCK_NONBLOCK) &&
			(ret == -EWOULDBLOCK || ret == -EAGAIN)) {
		return ret;
	}

	if (ret == -EAGAIN || ret == -ERESTARTSYS) {
		goto read_again;
	}
	else if (ret < 0) {
		printk(KERN_ERR "kernel_recvmsg %d", ret);
		return ret;
	}
	len += ret;
	if (len != expected_size) {
		printk(KERN_WARNING "ktcp_receive receive %d bytes which expected_size=%lu bytes, read again", len, expected_size);
		goto read_again;
	}

	return len;
}

int ktcp_receive(struct socket *sock, char *buffer, unsigned long flags,
		extent_t *extent)
{
	struct ktcp_hdr hdr;
	int ret;
	char *local_buffer = kmalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		return -ENOMEM;
	}

	hdr.length = 0xDEAD;
	ret = __ktcp_receive(sock, local_buffer, KTCP_BUFFER_SIZE, flags);
	if (ret < 0) {
		goto out;
	}

	memcpy(&hdr, local_buffer, sizeof(hdr));

	/* hdr.length is undetermined on process killed */
	if (unlikely(hdr.length > PAGE_SIZE)) {
		ret = -EFAULT;
		goto out;
	}
	memcpy(buffer, local_buffer + sizeof(hdr), hdr.length);

	if (extent) {
		*extent = hdr.extent;
	}

out:
	kfree(local_buffer);
	return ret < 0 ? ret : hdr.length;
}

int ktcp_connect(const char *host, const char *port, struct socket **conn_socket)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;

	if (host == NULL || port == NULL || conn_socket == NULL) {
		return -EINVAL;
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, conn_socket);
	if (ret < 0) {
		printk("sock_create %d\n", ret);
		return ret;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	kstrtol(port, 10, &portdec);
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

re_connect:
	ret = (*conn_socket)->ops->connect(*conn_socket, (struct sockaddr *)&saddr,
			sizeof(saddr), O_RDWR);
	if (ret == -EAGAIN || ret == -ERESTARTSYS) {
		goto re_connect;
	}

	if (ret && (ret != -EINPROGRESS)) {
		printk("connect %d\n", ret);
		sock_release(*conn_socket);
		return ret;
	}
	return SUCCESS;
}

int ktcp_listen(const char *host, const char *port, struct socket **listen_socket)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;

	BUILD_BUG_ON((sizeof(struct ktcp_hdr)) != (sizeof(uint16_t) +
				sizeof(extent_t)));

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, listen_socket);
	if (ret != 0) {
		printk(KERN_ERR "sock_create %d", ret);
		return ret;
	}
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	kstrtol(port, 10, &portdec);
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

	ret = (*listen_socket)->ops->bind(*listen_socket, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret != 0) {
		printk(KERN_ERR "bind %d\n", ret);
		sock_release(*listen_socket);
		return ret;
	}

	ret = (*listen_socket)->ops->listen(*listen_socket, DEFAULT_BACKLOG);
	if (ret != 0) {
		printk(KERN_ERR "listen %d\n", ret);
		sock_release(*listen_socket);
		return ret;
	}

	return SUCCESS;
}

int ktcp_accept(struct socket *listen_socket, struct socket **accept_socket, unsigned long flag)
{
	int ret;

	if (listen_socket == NULL) {
		printk(KERN_ERR "null listen_socket\n");
		return -EINVAL;
	}

	ret = sock_create_lite(listen_socket->sk->sk_family, listen_socket->sk->sk_type,
			listen_socket->sk->sk_protocol, accept_socket);
	if (ret != 0) {
		printk(KERN_ERR "sock_create %d\n", ret);
		return ret;
	}

re_accept:
	ret = listen_socket->ops->accept(listen_socket, *accept_socket, flag);
	if (ret == -ERESTARTSYS) {
		if (kthread_should_stop())
			return ret;
		goto re_accept;
	}
	// When setting SOCK_NONBLOCK flag, accept return this when there's nothing in waiting queue.
	if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
		sock_release(*accept_socket);
		*accept_socket = NULL;
		return ret;
	}
	if (ret < 0) {
		printk(KERN_ERR "accept %d\n", ret);
		sock_release(*accept_socket);
		*accept_socket = NULL;
		return ret;
	}

	(*accept_socket)->ops = listen_socket->ops;
	return SUCCESS;
}

int ktcp_release(struct socket *conn_socket)
{
	if (conn_socket == NULL) {
		return -EINVAL;
	}

	sock_release(conn_socket);
	return SUCCESS;
}
