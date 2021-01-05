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
 *   Boshi Yu <201608ybs@sjtu.edu.cn>
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

#define KTCP_RECV_BUF_SIZE 32

struct ktcp_hdr {
	size_t length;
	tx_add_t tx_add;
} __attribute__((packed));

typedef struct ktcp_msg
{
	uint16_t txid;
	void *recv_buf;
} ktcp_msg_t;

struct ktcp_cb
{
	struct mutex slock;
	struct mutex rlock;
	ktcp_msg_t recv_trans_buf[KTCP_RECV_BUF_SIZE];
	struct socket *socket;
};

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

int ktcp_send(struct ktcp_cb *cb, const char *buffer, size_t length,
		unsigned long flags, const tx_add_t *tx_add)
{
	int ret;
	mm_segment_t oldmm;
	struct ktcp_hdr hdr;
	char *local_buffer;

	mutex_lock(&cb->slock);
	hdr.tx_add = *tx_add;
	hdr.length = sizeof(hdr) + length;

	local_buffer = kzalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		mutex_unlock(&cb->slock);
		return -ENOMEM;
	}
	memcpy(local_buffer, &hdr, sizeof(hdr));
	memcpy(local_buffer + sizeof(hdr), buffer, length);

	// Get current address access limitdo
	oldmm = get_fs();
	set_fs(KERNEL_DS);
	ret = __ktcp_send(cb->socket, local_buffer, KTCP_BUFFER_SIZE, flags);
	
	// Retrieve address access limit
	set_fs(oldmm);
	kfree(local_buffer);
	mutex_unlock(&cb->slock);
	return ret < 0 ? ret : length;
}

static bool search_recv_buf(struct ktcp_cb *cb, uint16_t txid, ktcp_msg_t *msg)
{
	int i;

	for(i = 0; i < KTCP_RECV_BUF_SIZE; ++i)
	{
		if (cb->recv_trans_buf[i].txid == txid && cb->recv_trans_buf[i].recv_buf != NULL) {
				*msg = cb->recv_trans_buf[i];
				cb->recv_trans_buf[i].txid = 0;
				cb->recv_trans_buf[i].recv_buf = NULL;
				return true;
		}
	}
	return false;
}

static bool insert_into_recv_buf(struct ktcp_cb *cb, ktcp_msg_t msg)
{
	int i;

	for(i = 0; i < KTCP_RECV_BUF_SIZE; ++i)
	{ 
		if (cb->recv_trans_buf[i].txid == 0 && cb->recv_trans_buf[i].recv_buf == NULL) {
				cb->recv_trans_buf[i] = msg;
				return true;
		}
	}

	return false;
}

static int build_ktcp_recv_output(ktcp_msg_t msg, char *buffer, tx_add_t *tx_add)
{
	size_t real_length;
	struct ktcp_hdr hdr;
	memcpy(&hdr, (char *)msg.recv_buf, sizeof(struct ktcp_hdr));
	real_length = hdr.length - sizeof(struct ktcp_hdr);
	memcpy(buffer, (char *)msg.recv_buf + sizeof(struct ktcp_hdr), real_length);
	*tx_add = hdr.tx_add;
	kfree(msg.recv_buf);
	return real_length;
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
		.msg_flags   = flags | MSG_DONTWAIT,
	};

	if (expected_size == 0) {
		return 0;
	}

read_again:
	vec.iov_len = expected_size - len;
	vec.iov_base = buffer + len;
	ret = kernel_recvmsg(sock, &msg, &vec, 1, expected_size - len, flags | MSG_DONTWAIT);

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
		printk(KERN_ERR "kernel_recvmsg %d\n", ret);
		return ret;
	}
	len += ret;
	if (len != expected_size) {
		printk(KERN_WARNING "ktcp_receive receive %d bytes which expected_size=%lu bytes, read again", len, expected_size);
		goto read_again;
	}

	return len;
}

int ktcp_receive(struct ktcp_cb *cb, char *buffer, unsigned long flags,
		tx_add_t *tx_add)
{
	struct ktcp_hdr hdr;
	int ret;
	ktcp_msg_t msg;
	uint32_t usec_sleep = 0;
	char *local_buffer;

	BUG_ON(cb == NULL || buffer == NULL || tx_add == NULL);

	mutex_lock(&cb->rlock);
repoll:
	if (search_recv_buf(cb, tx_add->txid, &msg)){
		ret = build_ktcp_recv_output(msg, buffer, tx_add);
		mutex_unlock(&cb->rlock);
		return ret;
	}
	local_buffer = kzalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		ret = -ENOMEM;
		goto out;
	}
	ret = __ktcp_receive(cb->socket, local_buffer, KTCP_BUFFER_SIZE, flags);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			mutex_unlock(&cb->rlock);
			usec_sleep = (usec_sleep + 1) > 1000 ? 1000 : (usec_sleep + 1);
			usleep_range(usec_sleep, usec_sleep);
			mutex_lock(&cb->rlock);
			kfree(local_buffer);
			goto repoll;
		}
		kfree(local_buffer);
		printk(KERN_ERR "%s: __ktcp_receive error, ret %d\n",
				__func__, ret);
		goto out;
	}
	usec_sleep = 0;
	memcpy(&hdr, local_buffer, sizeof(hdr));
	msg.recv_buf = local_buffer;
	msg.txid = hdr.tx_add.txid;
	if (hdr.tx_add.txid != tx_add->txid && tx_add->txid != 0xFF){
		while(!insert_into_recv_buf(cb, msg)){
			mutex_unlock(&cb->rlock);
			usec_sleep = (usec_sleep + 1) > 1000 ? 1000 : (usec_sleep + 1);
			usleep_range(usec_sleep, usec_sleep);
			mutex_lock(&cb->rlock);
		}
		usec_sleep = 0;
		goto repoll;
	}
	else{
		build_ktcp_recv_output(msg, buffer, tx_add);
	}
out:
	mutex_unlock(&cb->rlock);
	return ret < 0 ? ret : hdr.length - sizeof(struct ktcp_hdr);
}

static int ktcp_create_cb(struct ktcp_cb **cbp)
{
	int i;
	struct ktcp_cb *cb;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	
	for(i = 0; i < KTCP_RECV_BUF_SIZE; ++i){
		cb->recv_trans_buf[i].txid = 0;
		cb->recv_trans_buf[i].recv_buf = NULL;
	}

	*cbp = cb;
	return 0;
}

int ktcp_connect(const char *host, const char *port, struct ktcp_cb **conn_cb)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;
	struct ktcp_cb *cb;
	struct socket *conn_socket;

	if (host == NULL || port == NULL || conn_cb == NULL) {
		return -EINVAL;
	}

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb fail, return %d\n",
				__func__, ret);
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
	if (ret < 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		return ret;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	kstrtol(port, 10, &portdec);
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

re_connect:
	ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr,
			sizeof(saddr), O_RDWR);
	if (ret == -EAGAIN || ret == -ERESTARTSYS) {
		goto re_connect;
	}

	if (ret && (ret != -EINPROGRESS)) {
		printk(KERN_ERR "%s: connct failed, return %d\n", __func__, ret);
		sock_release(conn_socket);
		return ret;
	}

	cb->socket = conn_socket;
	mutex_init(&cb->slock);
	mutex_init(&cb->rlock);
	*conn_cb = cb;
	return SUCCESS;
}

int ktcp_listen(const char *host, const char *port, struct ktcp_cb **listen_cb)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;
	struct ktcp_cb *cb;
	struct socket *listen_socket;

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb failed, return %d\n",
				__func__, ret);
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_socket);
	if (ret != 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		return ret;
	}
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	kstrtol(port, 10, &portdec);
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

	ret = listen_socket->ops->bind(listen_socket, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret != 0) {
		printk(KERN_ERR "%s: bind failed, return %d\n", __func__, ret);
		sock_release(listen_socket);
		return ret;
	}

	ret = listen_socket->ops->listen(listen_socket, DEFAULT_BACKLOG);
	if (ret != 0) {
		printk(KERN_ERR "%s: listen failed, return %d\n", __func__, ret);
		sock_release(listen_socket);
		return ret;
	}

	cb->socket = listen_socket;
	*listen_cb = cb;
	return SUCCESS;
}

int ktcp_accept(struct ktcp_cb *listen_cb, struct ktcp_cb **accept_cb, unsigned long flag)
{
	int ret;
	struct ktcp_cb *cb;
	struct socket *listen_socket, *accept_socket;

	if (listen_cb == NULL || (listen_socket = listen_cb->socket) == NULL) {
		printk(KERN_ERR "%s: null listen_cb\n", __func__);
		return -EINVAL;
	}

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb failed, return %d\n",
				__func__, ret);
	}

	ret = sock_create_lite(listen_socket->sk->sk_family, listen_socket->sk->sk_type,
			listen_socket->sk->sk_protocol, &accept_socket);
	if (ret != 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		return ret;
	}

re_accept:
	ret = listen_socket->ops->accept(listen_socket, accept_socket, flag);
	if (ret == -ERESTARTSYS) {
		if (kthread_should_stop())
			return ret;
		goto re_accept;
	}
	// When setting SOCK_NONBLOCK flag, accept return this when there's nothing in waiting queue.
	if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
		sock_release(accept_socket);
		accept_socket = NULL;
		return ret;
	}
	if (ret < 0) {
		printk(KERN_ERR "%s: accept failed, return %d\n", __func__, ret);
		sock_release(accept_socket);
		accept_socket = NULL;
		return ret;
	}

	accept_socket->ops = listen_socket->ops;
	cb->socket = accept_socket;
	mutex_init(&cb->slock);
	mutex_init(&cb->rlock);
	*accept_cb = cb;

	return SUCCESS;
}

int ktcp_release(struct ktcp_cb *conn_cb)
{
	if (conn_cb == NULL) {
		return -EINVAL;
	}

	sock_release(conn_cb->socket);
	return SUCCESS;
}
