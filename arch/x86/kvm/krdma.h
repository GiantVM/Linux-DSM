#ifndef __KVM_X86_KRDMA_H
#define __KVM_X86_KRDMA_H
/*
 * Copyright (C) 2019, Trusted Cloud Group, Shanghai Jiao Tong University.
 *
 * Authors:
 *   Yubin Chen <binsschen@sjtu.edu.cn>
 *   Jin Zhang <jzhang3002@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */
#include <linux/pci.h>
#include <linux/list.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#define RDMA_RESOLVE_TIMEOUT 2000
#define RDMA_CONNECT_RETRY_MAX 3

#define RDMA_SEND_QUEUE_DEPTH 1
#define RDMA_RECV_QUEUE_DEPTH 32
#define RDMA_CQ_QUEUE_DEPTH (RDMA_SEND_QUEUE_DEPTH + RDMA_RECV_QUEUE_DEPTH)

#define RDMA_SEND_BUF_SIZE RDMA_SEND_QUEUE_DEPTH
#define RDMA_RECV_BUF_SIZE RDMA_RECV_QUEUE_DEPTH

#define RDMA_SEND_BUF_LEN (PAGE_SIZE * 1024)
#define RDMA_RECV_BUF_LEN (PAGE_SIZE * 1024)

typedef uint32_t imm_t;

struct tx_add;
typedef struct tx_add tx_add_t;
struct krdma_cb;

enum krdma_role {
	KRDMA_CLIENT_CONN = 0,
	KRDMA_LISTEN_CONN = 1,
	KRDMA_ACCEPT_CONN = 2,
};

enum krdma_code {
	SERVER_EXIT = 1000,
	CLIENT_EXIT,
	CLIENT_RETRY,
	STATE_ERROR,
};

void krdma_config(size_t max_buf_size);

int krdma_send(struct krdma_cb *cb, const char *buffer, size_t length,
		unsigned long flag, const tx_add_t *tx_add);

int krdma_receive(struct krdma_cb *cb, char *buffer, unsigned long flag,
		tx_add_t *tx_add);

int krdma_connect(const char *host, const char *port, struct krdma_cb **conn_cb);

int krdma_listen(const char *host, const char *port, struct krdma_cb **listen_cb);

int krdma_accept(struct krdma_cb *listen_cb, struct krdma_cb **accept_cb, unsigned long flag);

int krdma_release(struct krdma_cb *cb);

#endif /* __KVM_X86_KRDMA_H */
