/*
 * RDMA support for KVM software distributed memory
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/kvm_host.h>

#include "krdma.h"

static bool dbg = 0;
#define pgprintk(x...) do { if (dbg) printk(x); } while (0)

#define DYNAMIC_POLLING_INTERVAL

typedef enum { KRDMA_SEND, KRDMA_RECV } krdma_poll_type_t;

/*
 * Invalid: the slot has not been used.
 * Posted: the request has been posted into the sq/rq.
 * Polled: the request has been polled from the cq (but not been completed yet).
 */
enum krdma_trans_state { INVALID = 0, POSTED, POLLED };

typedef struct krdma_send_trans {
	/* For DMA */
	void *send_buf;
	dma_addr_t send_dma_addr;
	uint16_t txid;
	enum krdma_trans_state state;

	struct ib_sge send_sge;
	struct ib_send_wr sq_wr;
} krdma_send_trans_t;

typedef struct krdma_recv_trans {
	/* For DMA */
	void *recv_buf;
	imm_t imm;
	dma_addr_t recv_dma_addr;
	size_t length;
	uint16_t txid;
	enum krdma_trans_state state;

	struct ib_sge recv_sge;
	struct ib_recv_wr rq_wr;
} krdma_recv_trans_t;

/* control block */
struct krdma_cb {
	struct mutex slock;
	struct mutex rlock;

	enum krdma_role role;

	enum {
		KRDMA_INIT = 0,
		KRDMA_ADDR_RESOLVED = 1,
		KRDMA_ROUTE_RESOLVED = 2,
		KRDMA_CONNECTED = 3,
		KRDMA_FLUSHING = 4,
		KRDMA_CLOSING = 5,
		KRDMA_CLOSED = 6,
		KRDMA_SEND_DONE = 7,
		KRDMA_RECV_DONE = 8,
		KRDMA_ERROR = 9,
		KRDMA_CONNECT_REJECTED = 10,
		KRDMA_DISCONNECTED = 11,
	} state;

	/* Communication Manager id */
	struct rdma_cm_id *cm_id;

	/* Completion Queue */
	struct ib_cq *send_cq;
	struct ib_cq *recv_cq;
	/* Protection Domain */
	struct ib_pd *pd;
	/* Queue Pair */
	struct ib_qp *qp;

	/*
	 * The buffers to buffer async requests.
	 */
	krdma_send_trans_t send_trans_buf[RDMA_SEND_BUF_SIZE];
	krdma_recv_trans_t recv_trans_buf[RDMA_RECV_BUF_SIZE];

	struct completion cm_done;

	struct list_head list;

	struct list_head ready_conn;
	struct list_head active_conn;

	int retry_count;
};

int krdma_create_cb(struct krdma_cb **cbp, enum krdma_role role)
{
	struct krdma_cb *cb;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	init_completion(&cb->cm_done);

	cb->role = role;
	if (cb->role == KRDMA_LISTEN_CONN) {
		INIT_LIST_HEAD(&cb->ready_conn);
		INIT_LIST_HEAD(&cb->active_conn);
	}

	*cbp = cb;
	return 0;
}

static int krdma_cma_event_handler(struct rdma_cm_id *cm_id,
		struct rdma_cm_event *event)
{
	int ret;
	struct krdma_cb *cb = cm_id->context;
	struct krdma_cb *conn_cb = NULL;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		pgprintk("%s: RDMA_CM_EVENT_ADDR_RESOLVED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_ADDR_RESOLVED;
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		pgprintk("%s: RDMA_CM_EVENT_ROUTE_RESOLVED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_ROUTE_RESOLVED;
		break;

	case RDMA_CM_EVENT_ROUTE_ERROR:
		pgprintk("%s: RDMA_CM_EVENT_ROUTE_ERROR, cm_id %p, error %d\n",
				__func__, cm_id, event->status);
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		pgprintk("%s: RDMA_CM_EVENT_CONNECT_REQUEST, cm_id %p\n",
				__func__, cm_id);
		/* create a new cb */
		ret = krdma_create_cb(&conn_cb, KRDMA_ACCEPT_CONN);
		if (!ret) {
			conn_cb->cm_id = cm_id;
			cm_id->context = conn_cb;
			list_add_tail(&conn_cb->list, &cb->ready_conn);
		} else {
			printk(KERN_ERR "%s: krdma_create_cb fail, ret %d\n",
					__func__, ret);
			cb->state = KRDMA_ERROR;
		}
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		pgprintk("%s: RDMA_CM_EVENT_ESTABLISHED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_CONNECTED;
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		pgprintk(KERN_ERR "%s: RDMA_CM_EVENT_DISCONNECTED, cm_id %p\n",
				__func__, cm_id);
		cb->state = KRDMA_DISCONNECTED;
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		printk(KERN_ERR "%s: RDMA_CM_EVENT %d, cm_id %p\n",
				__func__, event->event, cm_id);
		cb->state = KRDMA_CONNECT_REJECTED;
		break;
	default:
		pgprintk("%s: unknown event %d, cm_id %p\n",
				__func__, event->event, cm_id);
	}
	complete(&cb->cm_done);
	return 0;
}

int krdma_setup_buffers(struct krdma_cb *cb)
{
	int i;

	mutex_init(&cb->slock);
	mutex_init(&cb->rlock);

	memset(cb->send_trans_buf, 0, RDMA_SEND_BUF_SIZE *
			sizeof(krdma_send_trans_t));
	memset(cb->recv_trans_buf, 0, RDMA_RECV_BUF_SIZE *
			sizeof(krdma_recv_trans_t));

	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		cb->send_trans_buf[i].send_buf = ib_dma_alloc_coherent(cb->pd->device,
				RDMA_SEND_BUF_LEN, &cb->send_trans_buf[i].send_dma_addr,
				GFP_KERNEL | GFP_DMA);
		if (!cb->send_trans_buf[i].send_buf) {
			printk(KERN_ERR "%s: ib_dma_alloc_coherent send_buf failed\n",
					 __func__);
			goto out_free_bufs;
		}

		cb->send_trans_buf[i].send_sge.lkey = cb->pd->local_dma_lkey;
		/* .length is set at runtime. */
		cb->send_trans_buf[i].send_sge.addr = cb->send_trans_buf[i].send_dma_addr;
		cb->send_trans_buf[i].sq_wr.next = NULL;
		/* .wr_id is set at runtime. */
		cb->send_trans_buf[i].sq_wr.sg_list = &cb->send_trans_buf[i].send_sge;
		cb->send_trans_buf[i].sq_wr.num_sge = 1;
		cb->send_trans_buf[i].sq_wr.opcode = IB_WR_SEND_WITH_IMM;
		cb->send_trans_buf[i].sq_wr.send_flags = IB_SEND_SIGNALED;
		/* .ex.imm_data is set at runtime. */
	}

	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		cb->recv_trans_buf[i].recv_buf = ib_dma_alloc_coherent(cb->pd->device,
				RDMA_RECV_BUF_LEN, &cb->recv_trans_buf[i].recv_dma_addr,
				GFP_KERNEL | GFP_DMA);
		if (!cb->recv_trans_buf[i].recv_buf) {
			printk(KERN_ERR "%s: ib_dma_alloc_coherent recv_buf failed\n",
					 __func__);
			goto out_free_bufs;
		}

		cb->recv_trans_buf[i].recv_sge.lkey = cb->pd->local_dma_lkey;
		cb->recv_trans_buf[i].recv_sge.length = RDMA_RECV_BUF_LEN;
		cb->recv_trans_buf[i].recv_sge.addr = cb->recv_trans_buf[i].recv_dma_addr;
		cb->recv_trans_buf[i].rq_wr.next = NULL;
		cb->recv_trans_buf[i].rq_wr.wr_id = i;
		cb->recv_trans_buf[i].rq_wr.sg_list = &cb->recv_trans_buf[i].recv_sge;
		cb->recv_trans_buf[i].rq_wr.num_sge = 1;
	}

	return 0;

out_free_bufs:
	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		if (cb->send_trans_buf[i].send_buf) {
			ib_dma_free_coherent(cb->pd->device, RDMA_SEND_BUF_LEN,
					cb->send_trans_buf[i].send_buf,
					cb->send_trans_buf[i].send_dma_addr);
		}
	}
	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		if (cb->recv_trans_buf[i].recv_buf) {
			ib_dma_free_coherent(cb->pd->device, RDMA_RECV_BUF_LEN,
					cb->recv_trans_buf[i].recv_buf,
					cb->recv_trans_buf[i].recv_dma_addr);
		}
	}
	return -ENOMEM;
}

int krdma_free_buffers(struct krdma_cb *cb)
{
	int i;

	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		if (cb->send_trans_buf[i].send_buf) {
			ib_dma_free_coherent(cb->pd->device, RDMA_SEND_BUF_LEN,
					cb->send_trans_buf[i].send_buf,
					cb->send_trans_buf[i].send_dma_addr);
			cb->send_trans_buf[i].send_buf = NULL;
		}
	}
	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		if (cb->recv_trans_buf[i].recv_buf) {
			ib_dma_free_coherent(cb->pd->device, RDMA_RECV_BUF_LEN,
					cb->recv_trans_buf[i].recv_buf,
					cb->recv_trans_buf[i].recv_dma_addr);
		}
		cb->recv_trans_buf[i].recv_buf = NULL;
	}

	return 0;
}

static int krdma_post_recv(struct krdma_cb *cb);

static int krdma_connect_single(const char *host, const char *port,
		struct krdma_cb *cb)
{
	int ret;
	struct sockaddr_in addr;
	long portdec;
	struct ib_cq_init_attr cq_attr;
	struct ib_qp_init_attr qp_init_attr;
	struct rdma_conn_param conn_param;

	if (host == NULL || port == NULL || cb == NULL)
		return -EINVAL;

	/* Create cm_id */
	cb->cm_id = rdma_create_id(&init_net, krdma_cma_event_handler, cb,
					RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cb->cm_id)) {
		ret = PTR_ERR(cb->cm_id);
		printk(KERN_ERR "rdma_create_id error %d\n", ret);
		goto exit;
	}
	pgprintk("created cm_id %p\n", cb->cm_id);

	/* Resolve address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	kstrtol(port, 10, &portdec);
	addr.sin_addr.s_addr = in_aton(host);
	addr.sin_port = htons(portdec);
	ret = rdma_resolve_addr(cb->cm_id, NULL,
			(struct sockaddr *)&addr, RDMA_RESOLVE_TIMEOUT);
	if (ret) {
		printk(KERN_ERR "rdma_resolve_addr failed, ret %d\n", ret);
		goto free_cm_id;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_ADDR_RESOLVED) {
		ret = -STATE_ERROR;
		printk(KERN_ERR "rdma_resolve_route state error, ret %d\n", ret);
		goto exit;
	}
	pgprintk("rdma_resolve_addr succeed, device[%s] port_num[%u]\n",
			cb->cm_id->device->name, cb->cm_id->port_num);

	/* Resolve route. */
	ret = rdma_resolve_route(cb->cm_id, RDMA_RESOLVE_TIMEOUT);
	if (ret) {
		printk(KERN_ERR "rdma_resolve_route failed, ret %d\n", ret);
		goto free_cm_id;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_ROUTE_RESOLVED) {
		ret = -STATE_ERROR;
		printk(KERN_ERR "rdma_resolve_route state error, ret %d\n", ret);
		goto exit;
	}
	pgprintk("rdma_resolve_route succeed, cm_id %p\n", cb->cm_id);

	/* Create Protection Domain. */
	cb->pd = ib_alloc_pd(cb->cm_id->device, 0);
	if (IS_ERR(cb->pd)) {
		ret = PTR_ERR(cb->pd);
		printk(KERN_ERR "ib_alloc_pd failed\n");
		goto free_cm_id;
	}
	pgprintk("ib_alloc_pd succeed, cm_id %p\n", cb->cm_id);

	/* Create send Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->send_cq = ib_create_cq(cb->cm_id->device, NULL, NULL, cb, &cq_attr);
	if (IS_ERR(cb->send_cq)) {
		ret = PTR_ERR(cb->send_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_pd;
	}

	/* Create recv Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->recv_cq = ib_create_cq(cb->cm_id->device, NULL, NULL, cb, &cq_attr);
	if (IS_ERR(cb->recv_cq)) {
		ret = PTR_ERR(cb->recv_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_send_cq;
	}

	pgprintk("ib_create_cq succeed, cm_id %p\n", cb->cm_id);

	/* Create Queue Pair. */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = RDMA_SEND_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_wr = RDMA_RECV_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_send_sge = 1;
	/* Mlx doesn't support inline sends for kernel QPs (yet) */
	qp_init_attr.cap.max_inline_data = 0;
	qp_init_attr.qp_type = IB_QPT_RC;
	qp_init_attr.send_cq = cb->send_cq;
	qp_init_attr.recv_cq = cb->recv_cq;
	qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	ret = rdma_create_qp(cb->cm_id, cb->pd, &qp_init_attr);
	if (ret) {
		printk(KERN_ERR "rdma_create_qp failed, ret %d\n", ret);
		goto free_recv_cq;
	}
	cb->qp = cb->cm_id->qp;
	pgprintk("ib_create_qp succeed, cm_id %p\n", cb->cm_id);

	/* Setup buffers. */
	ret = krdma_setup_buffers(cb);
	if (ret) {
		printk(KERN_ERR "krdma_setup_buffers failed, ret %d\n", ret);
		goto free_buffers;
	}

	mutex_lock(&cb->rlock);
	ret = krdma_post_recv(cb);
	if (ret) {
		printk(KERN_ERR "krdma_post_recv failed, ret %d\n", ret);
		mutex_unlock(&cb->rlock);
		goto free_buffers;
	}
	mutex_unlock(&cb->rlock);

	/* Connect to remote. */
	memset(&conn_param, 0, sizeof(conn_param));
	/*
	 * The maximum number of times that a data transfer operation
	 * should be retried on the connection when an error occurs. This setting controls
	 * the number of times to retry send, RDMA, and atomic operations when timeouts
	 * occur.
	 */
	conn_param.retry_count = 7;
	/*
	 * The maximum number of times that a send operation from the
	 * remote peer should be retried on a connection after receiving a receiver not
	 * ready (RNR) error.
	 */
	conn_param.rnr_retry_count = 7;

	ret = rdma_connect(cb->cm_id, &conn_param);
	if (ret) {
		printk(KERN_ERR "rdma_connect failed, ret %d\n", ret);
		goto free_buffers;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_CONNECTED) {
		printk(KERN_ERR "%s: wait for KRDMA_CONNECTED state, but get %d\n",
				__func__, cb->state);
		if (cb->state == KRDMA_CONNECT_REJECTED)
			ret = -CLIENT_RETRY;
		else
			ret = -CLIENT_EXIT;

		goto free_buffers;
	}
	pgprintk("krdma_connect_single succeed, cm_id %p\n", cb->cm_id);
	return 0;

free_buffers:
	krdma_free_buffers(cb);
	rdma_destroy_qp(cb->cm_id);
free_recv_cq:
	ib_destroy_cq(cb->recv_cq);
free_send_cq:
	ib_destroy_cq(cb->send_cq);
free_pd:
	ib_dealloc_pd(cb->pd);
free_cm_id:
	rdma_destroy_id(cb->cm_id);
	cb->cm_id = NULL;
exit:
	return ret;
}

int krdma_connect(const char *host, const char *port, struct krdma_cb **conn_cb)
{
	int ret;
	struct krdma_cb *cb;

	if (host == NULL || port == NULL || conn_cb == NULL)
		return -EINVAL;

	ret = krdma_create_cb(&cb, KRDMA_CLIENT_CONN);
	if (ret) {
		printk(KERN_ERR "%s: krdma_create_cb fail, ret %d\n",
				__func__, ret);
		return ret;
	}

retry:
	ret = krdma_connect_single(host, port, cb);
	if (ret == 0) {
		/*
		 * If multiple clients desire to connect to remote servers, only one of
		 * them can call this function. Others must be blocked even if conn_cb
		 * has not been set here. Then double checking whether conn_cb is
		 * non-NULL can ensure the correctness of lazy connection.
		 */
		smp_mb();
		*conn_cb = cb;
		printk("%s: %p krdma_connect succeed\n", __func__, cb);
		return 0;
	}
	if (ret == -CLIENT_RETRY &&
				++cb->retry_count < RDMA_CONNECT_RETRY_MAX) {
		printk(KERN_ERR "%s: krdma_connect_single failed, retry_count %d, " \
				"reconnecting...\n", __func__, cb->retry_count);
		msleep(1000);
		goto retry;
	}
	*conn_cb = NULL;
	printk(KERN_ERR "%s: krdma_connect_single failed, ret: %d\n",
			__func__, ret);
	return ret;
}

int krdma_listen(const char *host, const char *port, struct krdma_cb **listen_cb)
{
	int ret;
	long portdec;
	struct sockaddr_in addr;
	struct krdma_cb *cb;

	if (host == NULL || port == NULL || listen_cb == NULL)
		return -EINVAL;

	ret = krdma_create_cb(listen_cb, KRDMA_LISTEN_CONN);
	if (ret) {
		printk(KERN_ERR "%s: krdma_create_cb fail, ret %d\n",
				 __func__, ret);
		goto exit;
	}
	cb = *listen_cb;

	/* Create cm_id. */
	cb->cm_id = rdma_create_id(&init_net, krdma_cma_event_handler, cb,
			RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cb->cm_id)) {
		ret = PTR_ERR(cb->cm_id);
		printk(KERN_ERR "rdma_create_id error %d\n", ret);
		goto exit;
	}
	pgprintk("created cm_id %p\n", cb->cm_id);

	/* Bind address. */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	kstrtol(port, 10, &portdec);
	addr.sin_addr.s_addr = in_aton(host);
	addr.sin_port = htons(portdec);
	ret = rdma_bind_addr(cb->cm_id, (struct sockaddr *)&addr);
	if (ret) {
		printk(KERN_ERR "rdma_bind_addr failed, ret %d\n", ret);
		goto free_cm_id;
	}
	pgprintk("rdma_bind_addr succeed, device[%s] port_num[%u]\n",
			cb->cm_id->device->name, cb->cm_id->port_num);

	ret = rdma_listen(cb->cm_id, 3);
	if (ret) {
		printk(KERN_ERR "rdma_listen failed: %d\n", ret);
		goto free_cm_id;
	}
	pgprintk("rdma_listen start...\n");
	return 0;

free_cm_id:
	rdma_destroy_id(cb->cm_id);
exit:
	return ret;
}

int krdma_accept(struct krdma_cb *listen_cb, struct krdma_cb **accept_cb,
		unsigned long flag)
{
	int ret = 0;
	struct ib_cq_init_attr cq_attr;
	struct ib_qp_init_attr qp_init_attr;
	struct rdma_conn_param conn_param;
	struct krdma_cb *cb;

	if (listen_cb == NULL) {
		printk(KERN_ERR "%s: null listen_socket\n", __func__);
		ret = -EINVAL;
		goto exit;
	}

	while (list_empty(&listen_cb->ready_conn)) {
		wait_for_completion_interruptible(&listen_cb->cm_done);
		if (listen_cb->state == KRDMA_ERROR) {
			printk(KERN_ERR "%s: rdma_listen cancel\n", __func__);
			ret = -SERVER_EXIT;
			goto exit;
		}
		if (kthread_should_stop()) {
			ret = -SERVER_EXIT;
			goto exit;
		}
	}

	/* Pick a ready connnection. */
	cb = list_first_entry(&listen_cb->ready_conn, struct krdma_cb, list);
	list_del(&cb->list);
	list_add_tail(&cb->list, &listen_cb->active_conn);
	*accept_cb = cb;

	pgprintk("get connection, cm_id %p\n", cb->cm_id);

	/* Create Protection Domain. */
	cb->pd = ib_alloc_pd(cb->cm_id->device, 0);
	if (IS_ERR(cb->pd)) {
		printk(KERN_ERR "ib_alloc_pd failed\n");
		goto free_conn_cm_id;
	}
	pgprintk("ib_alloc_pd succeed, cm_id %p\n", cb->cm_id);

	/* Create send Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->send_cq = ib_create_cq(cb->cm_id->device, NULL, NULL, cb, &cq_attr);
	if (IS_ERR(cb->send_cq)) {
		ret = PTR_ERR(cb->send_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_pd;
	}

	/* Create recv Completion Queue. */
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDMA_CQ_QUEUE_DEPTH;
	cq_attr.comp_vector = 0;
	cb->recv_cq = ib_create_cq(cb->cm_id->device, NULL, NULL, cb, &cq_attr);
	if (IS_ERR(cb->recv_cq)) {
		ret = PTR_ERR(cb->recv_cq);
		printk(KERN_ERR "ib_create_cq failed, ret%d\n", ret);
		goto free_send_cq;
	}

	pgprintk("ib_create_cq succeed, cm_id %p\n", cb->cm_id);

	/* Create Queue Pair. */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = RDMA_SEND_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_wr = RDMA_RECV_QUEUE_DEPTH;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_send_sge = 1;
	/* Mlx doesn't support inline sends for kernel QPs (yet) */
	qp_init_attr.cap.max_inline_data = 0;
	qp_init_attr.qp_type = IB_QPT_RC;
	qp_init_attr.send_cq = cb->send_cq;
	qp_init_attr.recv_cq = cb->recv_cq;
	qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	ret = rdma_create_qp(cb->cm_id, cb->pd, &qp_init_attr);
	if (ret) {
		printk(KERN_ERR "rdma_create_qp failed, ret %d\n", ret);
		goto free_recv_cq;
	}
	cb->qp = cb->cm_id->qp;
	pgprintk("ib_create_qp succeed, cm_id %p\n", cb->cm_id);

	/* Setup buffers. */
	ret = krdma_setup_buffers(cb);
	if (ret) {
		printk(KERN_ERR "krdma_setup_buffers failed, ret %d\n", ret);
		goto free_buffers;
	}

	mutex_lock(&cb->rlock);
	ret = krdma_post_recv(cb);
	if (ret) {
		printk(KERN_ERR "krdma_post_recv failed, ret %d\n", ret);
		mutex_unlock(&cb->rlock);
		goto free_buffers;
	}
	mutex_unlock(&cb->rlock);

	/* Accept */
	memset(&conn_param, 0, sizeof conn_param);
	conn_param.retry_count = conn_param.rnr_retry_count = 7;

	ret = rdma_accept(cb->cm_id, &conn_param);
	if (ret) {
		printk(KERN_ERR "rdma_accept error: %d\n", ret);
		goto free_buffers;
	}
	wait_for_completion(&cb->cm_done);
	if (cb->state != KRDMA_CONNECTED) {
		printk(KERN_ERR "%s: wait for KRDMA_CONNECTED state, but get %d\n",
				 __func__, cb->state);
		goto free_buffers;
	}

	pgprintk("new connection accepted with the following attributes:\n"
		"local: %pI4:%d\nremote: %pI4:%d\n",
		&((struct sockaddr_in *)&cb->cm_id->route.addr.src_addr)->sin_addr.s_addr,
		ntohs(((struct sockaddr_in *)&cb->cm_id->route.addr.src_addr)->sin_port),
		&((struct sockaddr_in *)&cb->cm_id->route.addr.dst_addr)->sin_addr.s_addr,
		ntohs(((struct sockaddr_in *)&cb->cm_id->route.addr.dst_addr)->sin_port));

	return 0;

free_buffers:
	krdma_free_buffers(cb);
	rdma_destroy_qp(cb->cm_id);
free_recv_cq:
	ib_destroy_cq(cb->recv_cq);
free_send_cq:
	ib_destroy_cq(cb->send_cq);
free_pd:
	ib_dealloc_pd(cb->pd);
free_conn_cm_id:
	rdma_destroy_id(cb->cm_id);
	cb->cm_id = NULL;
exit:
	return ret;
}

int krdma_release(struct krdma_cb *cb)
{
	struct krdma_cb *entry = NULL;
	struct krdma_cb *this = NULL;

	if (cb == NULL)
		return -EINVAL;

	if (!cb->cm_id)
		return -EINVAL;

	rdma_disconnect(cb->cm_id);
	if (cb->cm_id->qp)
		rdma_destroy_qp(cb->cm_id);

	krdma_free_buffers(cb);
	if (cb->send_cq)
		ib_destroy_cq(cb->send_cq);
	if (cb->recv_cq)
		ib_destroy_cq(cb->recv_cq);

	if (cb->pd)
		ib_dealloc_pd(cb->pd);

	rdma_destroy_id(cb->cm_id);
	cb->cm_id = NULL;

	if (cb->role == KRDMA_LISTEN_CONN) {
		list_for_each_entry_safe(entry, this, &cb->ready_conn, list) {
			krdma_release(entry);
			list_del(&entry->list);
		}
		list_for_each_entry_safe(entry, this, &cb->active_conn, list) {
			krdma_release(entry);
			list_del(&entry->list);
		}
	}

	return 0;
}

static int krdma_post_recv(struct krdma_cb *cb);
/* @return wr_id of wc if polling succeed. */
static int krdma_poll(struct krdma_cb *cb, imm_t *imm, size_t *length,
		bool block, krdma_poll_type_t type)
{
	struct ib_wc wc;
	int ret = 0;
	int retry_cnt = 0;
	struct ib_cq *cq;
#ifdef DYNAMIC_POLLING_INTERVAL
	uint32_t usec_sleep = 1;
#endif

	might_sleep();

	switch (type) {
	case KRDMA_SEND:
		cq = cb->send_cq;
		break;
	case KRDMA_RECV:
		cq = cb->recv_cq;
		break;
	default:
		return -EINVAL;
	}

repoll:
	switch (cb->state) {
		case KRDMA_ERROR:
			return -STATE_ERROR;
		case KRDMA_DISCONNECTED:
			return -EPIPE;
		default:
			break;
			/* Okay by default. */
	}
	/* Spin waiting for send/recv completion */
	while ((ret = ib_poll_cq(cq, 1, &wc) == 1)) {
		if (wc.status != IB_WC_SUCCESS) {
			if (wc.status == IB_WC_WR_FLUSH_ERR)
				continue;
			printk(KERN_ERR "%s: wc.status: %s wr.id %llu\n", __func__,
					ib_wc_status_msg(wc.status), wc.wr_id);
			return -STATE_ERROR;
		}

		if (imm && (wc.wc_flags & IB_WC_WITH_IMM)) {
			*imm = ntohl(wc.ex.imm_data);
		}
		if (length && (wc.opcode == IB_WC_RECV)) {
			*length = wc.byte_len;
		}
		switch (wc.opcode) {
		case IB_WC_SEND:
			BUG_ON(type != KRDMA_SEND);
			pgprintk("cb %p send completion, wr_id 0x%llx retry %d times\n", cb, wc.wr_id, retry_cnt);
			break;
		case IB_WC_RECV:
			BUG_ON(type != KRDMA_RECV);
			pgprintk("cb %p recv completion, wr_id 0x%llx\n", cb, wc.wr_id);
			if ((ret = (krdma_post_recv(cb))) < 0) {
				return -STATE_ERROR;
			}
			break;
		default:
			printk(KERN_ERR "%s: Unexpected opcode %u\n",
					__func__, wc.opcode);
			BUG();
		}
		return wc.wr_id;
	}
	if (ret == 0) {
		/*
		 * Occasionally, we will take CPU for too long and cause RCU to stuck,
		 * because interrupt and preemption are disabled in ib_poll_cq and thus
		 * the window for preemption is small. For this reason, we voluntarily
		 * call schedule() here.
		 */
		if (block) {
			retry_cnt++;
			/*
			 * Most send requests complete in 20~60 polls (At least for local
			 * loop back.
			 */
			if (retry_cnt > 128) {
#ifdef DYNAMIC_POLLING_INTERVAL
				/* A TCP-like Additive Increase and Multiplicative Decrease rule. */
				usec_sleep = (usec_sleep + 1) > 1000 ? 1000 : (usec_sleep + 1);
				usleep_range(usec_sleep, usec_sleep);
#else
				schedule();
#endif
			}
			if (retry_cnt >= 10000 && retry_cnt % 10000 == 0) {
				/* Issue warning per ~10s */
				printk(KERN_ERR "cb %p waiting for send too LONG!\n", cb);
			}
			goto repoll;
		}
		else {
			return -EAGAIN;
		}
	}
	return ret;
}

static bool search_send_buf(struct krdma_cb *cb, uint16_t txid,
		krdma_send_trans_t **trans, enum krdma_trans_state state)
{
	int i;

	for (i = 0; i < RDMA_SEND_BUF_SIZE; i++) {
		if (cb->send_trans_buf[i].state == state && cb->send_trans_buf[i].txid
				== txid) {
			*trans = &cb->send_trans_buf[i];
			return true;
		}
	}
	return false;
}

static bool search_recv_buf(struct krdma_cb *cb, uint16_t txid,
		krdma_recv_trans_t **trans, enum krdma_trans_state state)
{
	int i;

	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		if (cb->recv_trans_buf[i].state == state &&
				(cb->recv_trans_buf[i].txid == txid || txid == 0xFF)) {
			*trans = &cb->recv_trans_buf[i];
			return true;
		}
	}
	return false;
}

static int search_empty_send_buf(struct krdma_cb *cb, krdma_send_trans_t **trans)
{
	int i;

	/* TODO: Is this necessary? */
	static int last_schedule = 0;

	last_schedule = (last_schedule + 1) % RDMA_SEND_BUF_SIZE;

	for (i = last_schedule; i < last_schedule + RDMA_SEND_BUF_SIZE; i++) {
		if (cb->send_trans_buf[i % RDMA_SEND_BUF_SIZE].state == INVALID) {
			*trans = &cb->send_trans_buf[i % RDMA_SEND_BUF_SIZE];
			last_schedule = i % RDMA_SEND_BUF_SIZE;
			return i % RDMA_SEND_BUF_SIZE;
		}
	}
	/* Buffer overflow */
	BUG();
}

static int search_empty_recv_buf(struct krdma_cb *cb, krdma_recv_trans_t **trans)
{
	int i;

	for (i = 0; i < RDMA_RECV_BUF_SIZE; i++) {
		if (cb->recv_trans_buf[i].state == INVALID) {
			*trans = &cb->recv_trans_buf[i];
			return i;
		}
	}
	return -ENOENT;
}

static void build_posted_send_trans(const struct krdma_cb *cb, uint16_t txid,
		krdma_send_trans_t *trans) {
	trans->txid = txid;
	trans->state = POSTED;
}

static void build_posted_recv_trans(const struct krdma_cb *cb,
		krdma_recv_trans_t *trans) {
	trans->state = POSTED;
}

/* trans->length should be correctly set before calling this function. */
static uint16_t get_trans_txid(krdma_recv_trans_t *trans) {
	tx_add_t tx_add;

	memcpy(&tx_add, &trans->imm, sizeof(imm_t));
	memcpy(((char *)&tx_add) + sizeof(imm_t), trans->recv_buf + (trans->length
		- (sizeof(tx_add_t) - sizeof(imm_t))),
		sizeof(tx_add_t) - sizeof(imm_t));

	return tx_add.txid;
}

static void build_polled_recv_trans(const struct krdma_cb *cb, imm_t imm,
		size_t length, krdma_recv_trans_t *trans) {
	trans->imm = imm;
	trans->length = length;

	trans->txid = get_trans_txid(trans);
	trans->state = POLLED;
}

static void build_krdma_send_output(const struct krdma_cb *cb,
		krdma_send_trans_t *trans)
{
	trans->state = INVALID;
}

/*
 * Content + additional(without first 32-bit data, which is store in imm)
 *
 * imm:
 * |<---1st part of tx_add, i.e., the first 32 bit--->|
 * payload: cb->recv_buf:
 * |<------------------------sz=wc.byte_len------------------------------->|
 * |<----real data (sz=ret_val of send/recv)--->|<---2nd part of tx_add--->|
 */
/* rdma transaction->krdma interfaces. */
static size_t build_krdma_recv_output(struct krdma_cb *cb,
		krdma_recv_trans_t *trans, char *buffer, tx_add_t *tx_add)
{
	size_t real_length = trans->length - (sizeof(tx_add_t) - sizeof(imm_t));

	memcpy(tx_add, &trans->imm, sizeof(imm_t));
	memcpy(((char *)tx_add) + sizeof(imm_t), trans->recv_buf + real_length,
			sizeof(tx_add_t) - sizeof(imm_t));
	memcpy(buffer, trans->recv_buf, real_length);

	trans->state = INVALID;

	return real_length;
}

static int krdma_post_recv(struct krdma_cb *cb)
{
	int ret = 0;
	int slot;
	krdma_recv_trans_t *recv_trans;
	struct ib_recv_wr *bad_wr;

	while ((slot = search_empty_recv_buf(cb, &recv_trans)) != -ENOENT) {
		build_posted_recv_trans(cb, recv_trans);
		ret = ib_post_recv(cb->qp, &cb->recv_trans_buf[slot].rq_wr, &bad_wr);
		if (ret) {
			printk(KERN_ERR "%s: ib_post_recv error, ret %d\n",
					__func__, ret);
			return -STATE_ERROR;
		}
	}

	return ret;
}

/*
 * @param tx_add the txid field should be set as input parameter, 0xFF denotes
 * acceptance all receiving requests.
 * wr_id means which slot is used for transmission.
 */
int krdma_receive(struct krdma_cb *cb, char *buffer, unsigned long flag,
		tx_add_t *tx_add)
{
	int ret;
	size_t len;
	imm_t imm;
	/* The desired txid. */
	uint16_t txid = tx_add->txid;
	uint16_t recv_txid;
	uint32_t usec_sleep = 0;
	krdma_recv_trans_t *recv_trans;
	int retry_cnt = 0;

	BUILD_BUG_ON(sizeof(tx_add_t) < sizeof(imm_t));

	pgprintk("%s: cb %p receive 0x%x\n", __func__, cb, tx_add->txid);

	mutex_lock(&cb->rlock);

repoll:
	/* Search in the buffer. */
	if (search_recv_buf(cb, txid, &recv_trans, POLLED)) {
		ret = build_krdma_recv_output(cb, recv_trans, buffer, tx_add);
		mutex_unlock(&cb->rlock);
		pgprintk("%s: cb %p find 0x%x in buffer\n", __func__, cb, tx_add->txid);

		return ret;
	}

	/* Not found in the buffer. */
	ret = krdma_poll(cb, &imm, &len, false, KRDMA_RECV);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			retry_cnt++;
			/*
			 * Besides the incrment of concurrency (only one task runnable each
			 * time) of krdma_receive, unlock here is also used to avoid some
			 * kinds (not clearly learnt) of deadlock.
			 */
			mutex_unlock(&cb->rlock);
			usec_sleep = (usec_sleep + 1) > 1000 ? 1000 : (usec_sleep + 1);
			usleep_range(usec_sleep, usec_sleep);
			if ((flag & SOCK_NONBLOCK) && retry_cnt > 128) {
				return -EAGAIN;
			}
			mutex_lock(&cb->rlock);
			goto repoll;
		}
		mutex_unlock(&cb->rlock);
		printk(KERN_ERR "%s: krdma_poll error, ret %d\n",
				__func__, ret);
		return ret;
	}
	usec_sleep = 0;

	recv_trans = &cb->recv_trans_buf[ret];
	if (unlikely(recv_trans->state != POSTED)) {
		mutex_unlock(&cb->rlock);
		BUG();
	}
	build_polled_recv_trans(cb, imm, len, recv_trans);
	recv_txid = recv_trans->txid;

	/* Not my transaction. */
	if (txid != 0xFF && recv_txid != txid) {
		pgprintk("%s: cb %p wish 0x%x is 0x%x\n", __func__, cb, txid, recv_txid);
		goto repoll;
	}
	else {
		/* My transaction ! */
		build_krdma_recv_output(cb, recv_trans, buffer, tx_add);
		pgprintk("%s: cb %p find my tx 0x%x\n", __func__, cb, tx_add->txid);
	}

	mutex_unlock(&cb->rlock);
	pgprintk("%s: cb %p received 0x%x\n", __func__, cb, txid);
	return ret >= 0 ? len - (sizeof(tx_add_t) - sizeof(imm_t)) : ret;
}

/* wr_id of send means txid. */
int krdma_send(struct krdma_cb *cb, const char *buffer, size_t length,
		unsigned long flag, const tx_add_t *tx_add)
{
	int ret = 0;
	struct ib_send_wr *bad_wr;
	imm_t imm;
	krdma_send_trans_t *send_trans;
	uint16_t txid = tx_add->txid;
	size_t recv_length;
	int slot;

	mutex_lock(&cb->slock);

	slot = search_empty_send_buf(cb, &send_trans);
	build_posted_send_trans(cb, txid, send_trans);
	pgprintk("%s: cb %p send 0x%x length %lu\n", __func__, cb, send_trans->txid, length);

	cb->send_trans_buf[slot].send_sge.length = length + (sizeof(tx_add_t) - sizeof(imm_t));
	cb->send_trans_buf[slot].sq_wr.wr_id = tx_add->txid;
	cb->send_trans_buf[slot].sq_wr.ex.imm_data = htonl(*(const uint32_t*)tx_add);
	memcpy(cb->send_trans_buf[slot].send_buf + length, (((const char *)tx_add) + sizeof(imm_t)),
			sizeof(tx_add_t) - sizeof(imm_t));
	memcpy(cb->send_trans_buf[slot].send_buf, buffer, length);

	ret = ib_post_send(cb->qp, &cb->send_trans_buf[slot].sq_wr, &bad_wr);
	if (ret) {
		mutex_unlock(&cb->slock);
		printk(KERN_ERR "ib_post_send failed, ret %d\n", ret);
		return ret;
	}

	if (unlikely(search_send_buf(cb, txid, &send_trans, POLLED))) {
		mutex_unlock(&cb->slock);
		BUG();
	}

	ret = krdma_poll(cb, &imm, &recv_length, true, KRDMA_SEND);
	if (ret < 0) {
		mutex_unlock(&cb->slock);
		printk(KERN_ERR "%s: krdma_poll error, ret %d\n",
				__func__, ret);
		return ret;
	}

	/* Not my transaction, which should not happen. */
	if (unlikely(ret != txid)) {
		mutex_unlock(&cb->slock);
		BUG();
	}
	/* My transaction! */
	else {
		bool searched;
		searched = search_send_buf(cb, txid, &send_trans, POSTED);
		if (unlikely(!searched)) {
			mutex_unlock(&cb->slock);
			BUG();
		}
		build_krdma_send_output(cb, send_trans);
	}
	mutex_unlock(&cb->slock);

	pgprintk("%s: cb %p sent 0x%x\n", __func__, cb, txid);

	return ret >= 0 ? length : ret;
}
