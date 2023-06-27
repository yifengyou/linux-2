/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 * Copyright (C) 2008 Arne Redlich <agr@powerkom-dd.de>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/module.h>
#include <linux/hash.h>
#include <net/tcp.h>
#include <scsi/scsi.h>

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "iotype.h"

unsigned long debug_enable_flags;
unsigned long worker_thread_pool_size;

static struct kmem_cache *iscsi_cmnd_cache;
static u8 dummy_data[PAGE_SIZE];

static int ctr_major;
static char ctr_name[] = "ietctl";
extern struct file_operations ctr_fops;

static u32 cmnd_write_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_CMD_WRITE)
		return be32_to_cpu(hdr->data_length);
	return 0;
}

static u32 cmnd_read_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = cmnd_hdr(cmnd);

	if (hdr->flags & ISCSI_CMD_READ) {
		struct iscsi_rlength_ahdr *ahdr =
			(struct iscsi_rlength_ahdr *)cmnd->pdu.ahs;

		if (!(hdr->flags & ISCSI_CMD_WRITE))
			return be32_to_cpu(hdr->data_length);
		if (ahdr && ahdr->ahstype == ISCSI_AHSTYPE_RLENGTH)
			return be32_to_cpu(ahdr->read_length);
	}
	return 0;
}

static void iscsi_device_queue_cmnd(struct iscsi_cmnd *cmnd)
{
	set_cmnd_waitio(cmnd);
	wthread_queue(cmnd);
}

static void iscsi_scsi_queuecmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_queue *queue = &cmnd->lun->queue;

	dprintk(D_GENERIC, "%p\n", cmnd);

	if ((cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) != ISCSI_CMD_UNTAGGED &&
	    (cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) != ISCSI_CMD_SIMPLE) {
		cmnd->pdu.bhs.flags &= ~ISCSI_CMD_ATTR_MASK;
		cmnd->pdu.bhs.flags |= ISCSI_CMD_UNTAGGED;
	}

	spin_lock(&queue->queue_lock);

	set_cmnd_queued(cmnd);

	switch (cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
	case ISCSI_CMD_UNTAGGED:
	case ISCSI_CMD_SIMPLE:
		if (!list_empty(&queue->wait_list) || queue->ordered_cmnd)
			goto pending;
		queue->active_cnt++;
		break;

	default:
		BUG();
	}
	spin_unlock(&queue->queue_lock);

	iscsi_device_queue_cmnd(cmnd);
	return;
 pending:
	assert(list_empty(&cmnd->list));

	list_add_tail(&cmnd->list, &queue->wait_list);
	spin_unlock(&queue->queue_lock);
	return;
}

static void iscsi_scsi_dequeuecmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_queue *queue;

	if (!cmnd->lun)
		return;
	queue = &cmnd->lun->queue;
	spin_lock(&queue->queue_lock);
	switch (cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
	case ISCSI_CMD_UNTAGGED:
	case ISCSI_CMD_SIMPLE:
		--queue->active_cnt;
		break;
	case ISCSI_CMD_ORDERED:
	case ISCSI_CMD_HEAD_OF_QUEUE:
	case ISCSI_CMD_ACA:
		BUG();
	default:
		/* Should the iscsi_scsi_queuecmnd func reject this ? */
		break;
	}

	while (!list_empty(&queue->wait_list)) {
		cmnd = list_entry(queue->wait_list.next, struct iscsi_cmnd, list);
		switch ((cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK)) {
		case ISCSI_CMD_UNTAGGED:
		case ISCSI_CMD_SIMPLE:
			list_del_init(&cmnd->list);
			queue->active_cnt++;
			iscsi_device_queue_cmnd(cmnd);
			break;
		case ISCSI_CMD_ORDERED:
		case ISCSI_CMD_HEAD_OF_QUEUE:
		case ISCSI_CMD_ACA:
			BUG();
		}
	}

	spin_unlock(&queue->queue_lock);

	return;
}

/**
 * create a new command.
 *
 * iscsi_cmnd_create -
 * @conn: ptr to connection (for i/o)
 *
 * @return    ptr to command or NULL
 */

struct iscsi_cmnd *cmnd_alloc(struct iscsi_conn *conn, int req)
{
	struct iscsi_cmnd *cmnd;

	/* TODO: async interface is necessary ? */
	cmnd = kmem_cache_alloc(iscsi_cmnd_cache, GFP_KERNEL|__GFP_NOFAIL);

	memset(cmnd, 0, sizeof(*cmnd));
	INIT_LIST_HEAD(&cmnd->list);
	INIT_LIST_HEAD(&cmnd->pdu_list);
	INIT_LIST_HEAD(&cmnd->conn_list);
	INIT_LIST_HEAD(&cmnd->hash_list);
	cmnd->conn = conn;
	spin_lock(&conn->list_lock);
	atomic_inc(&conn->nr_cmnds);
	if (req)
		list_add_tail(&cmnd->conn_list, &conn->pdu_list);
	spin_unlock(&conn->list_lock);
	cmnd->tio = NULL;

	dprintk(D_GENERIC, "%p:%p\n", conn, cmnd);

	return cmnd;
}

/**
 * create a new command used as response.
 *
 * iscsi_cmnd_create_rsp_cmnd -
 * @cmnd: ptr to request command
 *
 * @return    ptr to response command or NULL
 */

static struct iscsi_cmnd *iscsi_cmnd_create_rsp_cmnd(struct iscsi_cmnd *cmnd, int final)
{
	struct iscsi_cmnd *rsp = cmnd_alloc(cmnd->conn, 0);

	if (final)
		set_cmnd_final(rsp);
	list_add_tail(&rsp->pdu_list, &cmnd->pdu_list);
	rsp->req = cmnd;
	return rsp;
}

static struct iscsi_cmnd *get_rsp_cmnd(struct iscsi_cmnd *req)
{
	return list_entry(req->pdu_list.prev, struct iscsi_cmnd, pdu_list);
}

static void iscsi_cmnds_init_write(struct list_head *send)
{
	struct iscsi_cmnd *cmnd = list_entry(send->next, struct iscsi_cmnd, list);
	struct iscsi_conn *conn = cmnd->conn;
	struct list_head *pos, *next;

	spin_lock(&conn->list_lock);

	list_for_each_safe(pos, next, send) {
		cmnd = list_entry(pos, struct iscsi_cmnd, list);

		dprintk(D_GENERIC, "%p:%x\n", cmnd, cmnd_opcode(cmnd));

		list_del_init(&cmnd->list);
		assert(conn == cmnd->conn);
		list_add_tail(&cmnd->list, &conn->write_list);
	}

	spin_unlock(&conn->list_lock);

	nthread_wakeup(conn->session->target);
}

static void iscsi_cmnd_init_write(struct iscsi_cmnd *cmnd)
{
	LIST_HEAD(head);

	if (!list_empty(&cmnd->list)) {
		eprintk("%x %x %x %x %lx %u %u %u %u %u %u %u %d %d\n",
			cmnd_itt(cmnd), cmnd_ttt(cmnd), cmnd_opcode(cmnd),
			cmnd_scsicode(cmnd), cmnd->flags, cmnd->r2t_sn,
			cmnd->r2t_length, cmnd->is_unsolicited_data,
			cmnd->target_task_tag, cmnd->outstanding_r2t,
			cmnd->hdigest, cmnd->ddigest,
			list_empty(&cmnd->pdu_list), list_empty(&cmnd->hash_list));

		assert(list_empty(&cmnd->list));
	}
	list_add(&cmnd->list, &head);
	iscsi_cmnds_init_write(&head);
}

static void do_send_data_rsp(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_cmnd *data_cmnd;
	struct tio *tio = cmnd->tio;
	struct iscsi_scsi_cmd_hdr *req = cmnd_hdr(cmnd);
	struct iscsi_data_in_hdr *rsp;
	u32 pdusize, expsize, scsisize, size, offset, sn;
	LIST_HEAD(send);

	dprintk(D_GENERIC, "%p\n", cmnd);
	pdusize = conn->session->param.max_xmit_data_length;
	expsize = cmnd_read_size(cmnd);
	size = min(expsize, tio->size);
	offset = 0;
	sn = 0;

	while (1) {
		data_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd, size <= pdusize);
		tio_get(tio);
		data_cmnd->tio = tio;
		rsp = (struct iscsi_data_in_hdr *)&data_cmnd->pdu.bhs;

		rsp->opcode = ISCSI_OP_SCSI_DATA_IN;
		rsp->itt = req->itt;
		rsp->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
		rsp->buffer_offset = offset;
		rsp->data_sn = cpu_to_be32(sn);

		if (size <= pdusize) {
			data_cmnd->pdu.datasize = size;
			rsp->flags = ISCSI_FLG_FINAL | ISCSI_FLG_STATUS;

			scsisize = tio->size;
			if (scsisize < expsize) {
				rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
				size = expsize - scsisize;
			} else if (scsisize > expsize) {
				rsp->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
				size = scsisize - expsize;
			} else
				size = 0;
			rsp->residual_count = cpu_to_be32(size);
			list_add_tail(&data_cmnd->list, &send);

			break;
		}

		data_cmnd->pdu.datasize = pdusize;

		size -= pdusize;
		offset += pdusize;
		sn++;

		list_add_tail(&data_cmnd->list, &send);
	}

	iscsi_cmnds_init_write(&send);
}

static struct iscsi_cmnd *create_scsi_rsp(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);
	struct iscsi_scsi_rsp_hdr *rsp_hdr;
	struct iscsi_sense_data *sense;

	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);

	rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_SCSI_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->response = ISCSI_RESPONSE_COMMAND_COMPLETED;
	rsp_hdr->cmd_status = req->status;
	rsp_hdr->itt = req_hdr->itt;

	if (req->status == SAM_STAT_CHECK_CONDITION) {
		assert(!rsp->tio);
		rsp->tio = tio_alloc(1);
		sense = (struct iscsi_sense_data *)
			page_address(rsp->tio->pvec[0]);

		assert(sense);
		clear_page(sense);
		sense->length = cpu_to_be16(IET_SENSE_BUF_SIZE);

		memcpy(sense->data, req->sense_buf, IET_SENSE_BUF_SIZE);
		rsp->pdu.datasize = sizeof(struct iscsi_sense_data) +
			IET_SENSE_BUF_SIZE;

		rsp->tio->size = (rsp->pdu.datasize + 3) & -4;
		rsp->tio->offset = 0;
	}

	return rsp;
}

void iscsi_cmnd_set_sense(struct iscsi_cmnd *cmnd, u8 sense_key, u8 asc,
			  u8 ascq)
{
	cmnd->status = SAM_STAT_CHECK_CONDITION;

	cmnd->sense_buf[0] = 0xf0;
	cmnd->sense_buf[2] = sense_key;
	cmnd->sense_buf[7] = 6;	// Additional sense length
	cmnd->sense_buf[12] = asc;
	cmnd->sense_buf[13] = ascq;
}

static struct iscsi_cmnd *create_sense_rsp(struct iscsi_cmnd *req,
					   u8 sense_key, u8 asc, u8 ascq)
{
	iscsi_cmnd_set_sense(req, sense_key, asc, ascq);
	return create_scsi_rsp(req);
}

void send_scsi_rsp(struct iscsi_cmnd *req, void (*func)(struct iscsi_cmnd *))
{
	struct iscsi_cmnd *rsp;
	struct iscsi_scsi_rsp_hdr *rsp_hdr;
	u32 size;

	func(req);
	rsp = create_scsi_rsp(req);

	switch (req->status) {
	case SAM_STAT_GOOD:
	case SAM_STAT_RESERVATION_CONFLICT:
		rsp_hdr = (struct iscsi_scsi_rsp_hdr *) &rsp->pdu.bhs;
		if ((size = cmnd_read_size(req)) != 0) {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(size);
		}
		break;
	default:
		break;
	}

	iscsi_cmnd_init_write(rsp);
}

void send_data_rsp(struct iscsi_cmnd *req, void (*func)(struct iscsi_cmnd *))
{
	struct iscsi_cmnd *rsp;

	func(req);

	if (req->status == SAM_STAT_GOOD)
		do_send_data_rsp(req);
	else {
		rsp = create_scsi_rsp(req);
		iscsi_cmnd_init_write(rsp);
	}
}

/**
 * Free a command.
 * Also frees the additional header.
 *
 * iscsi_cmnd_remove -
 * @cmnd: ptr to command
 */

static void iscsi_cmnd_remove(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn;

	if (!cmnd)
		return;

	if (cmnd_timer_active(cmnd)) {
		clear_cmnd_timer_active(cmnd);
		del_timer_sync(&cmnd->timer);
	}

	dprintk(D_GENERIC, "%p\n", cmnd);
	conn = cmnd->conn;
	kfree(cmnd->pdu.ahs);

	if (!list_empty(&cmnd->list)) {
		struct iscsi_scsi_cmd_hdr *req = cmnd_hdr(cmnd);

		eprintk("cmnd %p still on some list?, %x, %x, %x, %x, %x, %x, %x %lx\n",
			cmnd, req->opcode, req->scb[0], req->flags, req->itt,
			be32_to_cpu(req->data_length),
			req->cmd_sn, be32_to_cpu(cmnd->pdu.datasize),
			conn->state);

		if (cmnd->req) {
			struct iscsi_scsi_cmd_hdr *req = cmnd_hdr(cmnd->req);
			eprintk("%p %x %u\n", req, req->opcode, req->scb[0]);
		}
		dump_stack();
		BUG();
	}
	list_del(&cmnd->list);
	spin_lock(&conn->list_lock);
	atomic_dec(&conn->nr_cmnds);
	list_del(&cmnd->conn_list);
	spin_unlock(&conn->list_lock);

	if (cmnd->tio)
		tio_put(cmnd->tio);

	kmem_cache_free(iscsi_cmnd_cache, cmnd);
}

static void cmnd_skip_pdu(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct tio *tio = cmnd->tio;
	char *addr;
	u32 size;
	int i;

	eprintk("%x %x %x %u\n", cmnd_itt(cmnd), cmnd_opcode(cmnd),
		cmnd_hdr(cmnd)->scb[0], cmnd->pdu.datasize);

	if (!(size = cmnd->pdu.datasize))
		return;

	if (tio)
		assert(tio->pg_cnt > 0);
	else
		tio = cmnd->tio = tio_alloc(1);

	addr = page_address(tio->pvec[0]);
	assert(addr);
	size = (size + 3) & -4;
	conn->read_size = size;
	for (i = 0; size > PAGE_CACHE_SIZE; i++, size -= PAGE_CACHE_SIZE) {
		assert(i < ISCSI_CONN_IOV_MAX);
		conn->read_iov[i].iov_base = addr;
		conn->read_iov[i].iov_len = PAGE_CACHE_SIZE;
	}
	conn->read_iov[i].iov_base = addr;
	conn->read_iov[i].iov_len = size;
	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_msg.msg_iovlen = ++i;
}

static void iscsi_cmnd_reject(struct iscsi_cmnd *req, int reason)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_reject_hdr *rsp_hdr;
	struct tio *tio;
	char *addr;

	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);
	rsp_hdr = (struct iscsi_reject_hdr *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_REJECT;
	rsp_hdr->ffffffff = ISCSI_RESERVED_TAG;
	rsp_hdr->reason = reason;

	rsp->tio = tio = tio_alloc(1);
	addr = page_address(tio->pvec[0]);
	clear_page(addr);
	memcpy(addr, &req->pdu.bhs, sizeof(struct iscsi_hdr));
	tio->size = rsp->pdu.datasize = sizeof(struct iscsi_hdr);
	cmnd_skip_pdu(req);

	req->pdu.bhs.opcode = ISCSI_OP_PDU_REJECT;
}

static void cmnd_set_sn(struct iscsi_cmnd *cmnd, int set_stat_sn)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_session *sess = conn->session;

	if (set_stat_sn)
		cmnd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn++);
	cmnd->pdu.bhs.exp_sn = cpu_to_be32(sess->exp_cmd_sn);
	cmnd->pdu.bhs.max_sn = cpu_to_be32(sess->exp_cmd_sn + sess->max_queued_cmnds);
}

static void update_stat_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	u32 exp_stat_sn;

	cmnd->pdu.bhs.exp_sn = exp_stat_sn = be32_to_cpu(cmnd->pdu.bhs.exp_sn);
	dprintk(D_GENERIC, "%x,%x\n", cmnd_opcode(cmnd), exp_stat_sn);
	if ((int)(exp_stat_sn - conn->exp_stat_sn) > 0 &&
	    (int)(exp_stat_sn - conn->stat_sn) <= 0) {
		// free pdu resources
		cmnd->conn->exp_stat_sn = exp_stat_sn;
	}
}

static int check_cmd_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	u32 cmd_sn;

	cmnd->pdu.bhs.sn = cmd_sn = be32_to_cpu(cmnd->pdu.bhs.sn);
	dprintk(D_GENERIC, "%d(%d)\n", cmd_sn, session->exp_cmd_sn);
	if ((s32)(cmd_sn - session->exp_cmd_sn) >= 0)
		return 0;
	eprintk("sequence error (%x,%x)\n", cmd_sn, session->exp_cmd_sn);
	return -ISCSI_REASON_PROTOCOL_ERROR;
}

static struct iscsi_cmnd *__cmnd_find_hash(struct iscsi_session *session, u32 itt, u32 ttt)
{
	struct list_head *head;
	struct iscsi_cmnd *cmnd;

	head = &session->cmnd_hash[cmnd_hashfn(itt)];

	list_for_each_entry(cmnd, head, hash_list) {
		if (cmnd->pdu.bhs.itt == itt) {
			if ((ttt != ISCSI_RESERVED_TAG) && (ttt != cmnd->target_task_tag))
				continue;
			return cmnd;
		}
	}

	return NULL;
}

static struct iscsi_cmnd *cmnd_find_hash(struct iscsi_session *session, u32 itt, u32 ttt)
{
	struct iscsi_cmnd *cmnd;

	spin_lock(&session->cmnd_hash_lock);

	cmnd = __cmnd_find_hash(session, itt, ttt);

	spin_unlock(&session->cmnd_hash_lock);

	return cmnd;
}

static int cmnd_insert_hash_ttt(struct iscsi_cmnd *cmnd, u32 ttt)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;
	struct list_head *head;
	int err = 0;
	u32 itt = cmnd->pdu.bhs.itt;

	head = &session->cmnd_hash[cmnd_hashfn(itt)];

	spin_lock(&session->cmnd_hash_lock);

	tmp = __cmnd_find_hash(session, itt, ttt);
	if (!tmp) {
		list_add_tail(&cmnd->hash_list, head);
		set_cmnd_hashed(cmnd);
	} else
		err = -ISCSI_REASON_TASK_IN_PROGRESS;

	spin_unlock(&session->cmnd_hash_lock);

	return err;
}

static int cmnd_insert_hash(struct iscsi_cmnd *cmnd)
{
	int err;

	dprintk(D_GENERIC, "%p:%x\n", cmnd, cmnd->pdu.bhs.itt);

	if (cmnd->pdu.bhs.itt == ISCSI_RESERVED_TAG)
		return -ISCSI_REASON_PROTOCOL_ERROR;

	err = cmnd_insert_hash_ttt(cmnd, ISCSI_RESERVED_TAG);
	if (!err) {
		update_stat_sn(cmnd);
		err = check_cmd_sn(cmnd);
	}

	return err;
}

static void __cmnd_remove_hash(struct iscsi_cmnd *cmnd)
{
	list_del(&cmnd->hash_list);
}

static void cmnd_remove_hash(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *tmp;

	spin_lock(&session->cmnd_hash_lock);

	tmp = __cmnd_find_hash(session, cmnd->pdu.bhs.itt,
			       cmnd->target_task_tag);
	if (tmp && tmp == cmnd)
		__cmnd_remove_hash(tmp);
	else
		eprintk("%p:%x not found\n", cmnd, cmnd_itt(cmnd));

	spin_unlock(&session->cmnd_hash_lock);
}

static void cmnd_skip_data(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_scsi_rsp_hdr *rsp_hdr;
	u32 size;

	rsp = get_rsp_cmnd(req);
	rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
	if (cmnd_opcode(rsp) != ISCSI_OP_SCSI_RSP) {
		eprintk("unexpected response command %u\n", cmnd_opcode(rsp));
		return;
	}

	size = cmnd_write_size(req);
	if (size) {
		rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
		rsp_hdr->residual_count = cpu_to_be32(size);
	}
	size = cmnd_read_size(req);
	if (size) {
		if (cmnd_hdr(req)->flags & ISCSI_CMD_WRITE) {
			rsp_hdr->flags |= ISCSI_FLG_BIRESIDUAL_UNDERFLOW;
			rsp_hdr->bi_residual_count = cpu_to_be32(size);
		} else {
			rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp_hdr->residual_count = cpu_to_be32(size);
		}
	}
	req->pdu.bhs.opcode =
		(req->pdu.bhs.opcode & ~ISCSI_OPCODE_MASK) | ISCSI_OP_SCSI_REJECT;

	cmnd_skip_pdu(req);
}

static int cmnd_recv_pdu(struct iscsi_conn *conn, struct tio *tio, u32 offset, u32 size)
{
	int idx, i;
	char *addr;

	dprintk(D_GENERIC, "%p %u,%u\n", tio, offset, size);
	offset += tio->offset;

	if (!(offset < tio->offset + tio->size) ||
	    !(offset + size <= tio->offset + tio->size)) {
		eprintk("%u %u %u %u", offset, size, tio->offset, tio->size);
		return -EIO;
	}
	assert(offset < tio->offset + tio->size);
	assert(offset + size <= tio->offset + tio->size);

	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_size = size = (size + 3) & -4;
	conn->read_overflow = 0;

	i = 0;
	while (1) {
		assert(tio->pvec[idx]);
		addr = page_address(tio->pvec[idx]);
		assert(addr);
		conn->read_iov[i].iov_base =  addr + offset;
		if (offset + size <= PAGE_CACHE_SIZE) {
			conn->read_iov[i].iov_len = size;
			conn->read_msg.msg_iovlen = ++i;
			break;
		}
		conn->read_iov[i].iov_len = PAGE_CACHE_SIZE - offset;
		size -= conn->read_iov[i].iov_len;
		offset = 0;
		if (++i >= ISCSI_CONN_IOV_MAX) {
			conn->read_msg.msg_iovlen = i;
			conn->read_overflow = size;
			conn->read_size -= size;
			break;
		}

		idx++;
	}

	return 0;
}

static void set_offset_and_length(struct iet_volume *lu, u8 *cmd, loff_t *off, u32 *len)
{
	assert(lu);

	switch (cmd[0]) {
	case READ_6:
	case WRITE_6:
		*off = ((cmd[1] & 0x1f) << 16) + (cmd[2] << 8) + cmd[3];
		*len = cmd[4];
		if (!*len)
			*len = 256;
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		*off = (u32)cmd[2] << 24 | (u32)cmd[3] << 16 |
			(u32)cmd[4] << 8 | (u32)cmd[5];
		*len = (cmd[7] << 8) + cmd[8];
		break;
	case READ_16:
	case WRITE_16:
		*off = (u64)cmd[2] << 56 | (u64)cmd[3] << 48 |
			(u64)cmd[4] << 40 | (u64)cmd[5] << 32 |
			(u64)cmd[6] << 24 | (u64)cmd[7] << 16 |
			(u64)cmd[8] << 8 | (u64)cmd[9];
		*len = (u32)cmd[10] << 24 | (u32)cmd[11] << 16 |
			(u32)cmd[12] << 8 | (u32)cmd[13];
		break;
	default:
		BUG();
	}

	*off <<= lu->blk_shift;
	*len <<= lu->blk_shift;
}

static u32 translate_lun(u16 * data)
{
	u8 *p = (u8 *) data;
	u32 lun = ~0U;

	switch (*p >> 6) {
	case 0:
		lun = p[1];
		break;
	case 1:
		lun = (0x3f & p[0]) << 8 | p[1];
		break;
	case 2:
	case 3:
	default:
		eprintk("%u %u %u %u\n", data[0], data[1], data[2], data[3]);
		break;
	}

	return lun;
}

static void send_r2t(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;
	struct iscsi_r2t_hdr *rsp_hdr;
	u32 length, offset, burst;
	LIST_HEAD(send);

	length = req->r2t_length;
	burst = req->conn->session->param.max_burst_length;
	offset = be32_to_cpu(cmnd_hdr(req)->data_length) - length;

	do {
		rsp = iscsi_cmnd_create_rsp_cmnd(req, 0);
		rsp->pdu.bhs.ttt = req->target_task_tag;

		rsp_hdr = (struct iscsi_r2t_hdr *)&rsp->pdu.bhs;
		rsp_hdr->opcode = ISCSI_OP_R2T;
		rsp_hdr->flags = ISCSI_FLG_FINAL;
		memcpy(rsp_hdr->lun, cmnd_hdr(req)->lun, 8);
		rsp_hdr->itt = cmnd_hdr(req)->itt;
		rsp_hdr->r2t_sn = cpu_to_be32(req->r2t_sn++);
		rsp_hdr->buffer_offset = cpu_to_be32(offset);
		if (length > burst) {
			rsp_hdr->data_length = cpu_to_be32(burst);
			length -= burst;
			offset += burst;
		} else {
			rsp_hdr->data_length = cpu_to_be32(length);
			length = 0;
		}

		dprintk(D_WRITE, "%x %u %u %u %u\n", cmnd_itt(req),
			be32_to_cpu(rsp_hdr->data_length),
			be32_to_cpu(rsp_hdr->buffer_offset),
			be32_to_cpu(rsp_hdr->r2t_sn), req->outstanding_r2t);

		list_add_tail(&rsp->list, &send);

		if (++req->outstanding_r2t >= req->conn->session->param.max_outstanding_r2t)
			break;

	} while (length);

	iscsi_cmnds_init_write(&send);
}

static void scsi_cmnd_exec(struct iscsi_cmnd *cmnd)
{
	if (cmnd->r2t_length) {
		if (!cmnd->is_unsolicited_data)
			send_r2t(cmnd);
	} else {
		if (cmnd->lun) {
			iscsi_scsi_queuecmnd(cmnd);
		} else {
			iscsi_device_queue_cmnd(cmnd);
		}
	}
}

static int nop_out_start(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	u32 size, tmp;
	int i, err = 0;

	if (cmnd_ttt(cmnd) != cpu_to_be32(ISCSI_RESERVED_TAG)) {
		cmnd->req = cmnd_find_hash(conn->session, cmnd->pdu.bhs.itt,
					   cmnd->pdu.bhs.ttt);
		if (!cmnd->req) {
			/*
			 * We didn't request this NOP-Out (by sending a
			 * NOP-In, see 10.18.2 of the RFC) or our fake NOP-Out
			 * timed out.
			 */
			eprintk("initiator bug %x\n", cmnd_itt(cmnd));
			err = -ISCSI_REASON_PROTOCOL_ERROR;
			goto out;
		}

		del_timer_sync(&cmnd->req->timer);
		clear_cmnd_timer_active(cmnd->req);
		dprintk(D_GENERIC, "NOP-Out: %p, ttt %x, timer %p\n",
			cmnd->req, cmnd_ttt(cmnd->req), &cmnd->req->timer);
	}

	if (cmnd_itt(cmnd) == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		if (!(cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE))
			eprintk("%s\n", "initiator bug!");
		update_stat_sn(cmnd);
		err = check_cmd_sn(cmnd);
		if (err)
			goto out;
	} else if ((err = cmnd_insert_hash(cmnd)) < 0) {
		eprintk("ignore this request %x\n", cmnd_itt(cmnd));
		goto out;
	}

	if ((size = cmnd->pdu.datasize)) {
		size = (size + 3) & -4;
		conn->read_msg.msg_iov = conn->read_iov;
		if (cmnd->pdu.bhs.itt != cpu_to_be32(ISCSI_RESERVED_TAG)) {
			struct tio *tio;
			int pg_cnt = get_pgcnt(size, 0);

			assert(pg_cnt < ISCSI_CONN_IOV_MAX);
			cmnd->tio = tio = tio_alloc(pg_cnt);
			tio_set(tio, size, 0);

			for (i = 0; i < pg_cnt; i++) {
				conn->read_iov[i].iov_base
					= page_address(tio->pvec[i]);
				tmp = min_t(u32, size, PAGE_CACHE_SIZE);
				conn->read_iov[i].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
			}
		} else {
			for (i = 0; i < ISCSI_CONN_IOV_MAX; i++) {
				conn->read_iov[i].iov_base = dummy_data;
				tmp = min_t(u32, size, sizeof(dummy_data));
				conn->read_iov[i].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
			}
		}
		assert(!size);
		conn->read_overflow = size;
		conn->read_msg.msg_iovlen = i;
	}

out:
	return err;
}

static u32 get_next_ttt(struct iscsi_session *session)
{
	u32 ttt;

	if (session->next_ttt == ISCSI_RESERVED_TAG)
		session->next_ttt++;
	ttt = session->next_ttt++;

	return cpu_to_be32(ttt);
}

static void scsi_cmnd_start(struct iscsi_conn *conn, struct iscsi_cmnd *req)
{
	struct iscsi_scsi_cmd_hdr *req_hdr = cmnd_hdr(req);

	dprintk(D_GENERIC, "scsi command: %02x\n", req_hdr->scb[0]);

	req->lun = volume_get(conn->session->target, translate_lun(req_hdr->lun));
	if (!req->lun) {
		switch (req_hdr->scb[0]) {
		case INQUIRY:
		case REPORT_LUNS:
			break;
		default:
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->scb[0]);
			create_sense_rsp(req, ILLEGAL_REQUEST, 0x25, 0x0);
			cmnd_skip_data(req);
			goto out;
		}
	} else
		set_cmnd_lunit(req);

	switch (req_hdr->scb[0]) {
	case SERVICE_ACTION_IN:
		if ((req_hdr->scb[1] & 0x1f) != 0x10)
			goto error;
	case INQUIRY:
	case REPORT_LUNS:
	case TEST_UNIT_READY:
	case SYNCHRONIZE_CACHE:
	case VERIFY:
	case VERIFY_16:
	case START_STOP:
	case READ_CAPACITY:
	case MODE_SENSE:
	case REQUEST_SENSE:
	case RESERVE:
	case RELEASE:
	{
		if (!(req_hdr->flags & ISCSI_CMD_FINAL) || req->pdu.datasize) {
			/* unexpected unsolicited data */
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->scb[0]);
			create_sense_rsp(req, ABORTED_COMMAND, 0xc, 0xc);
			cmnd_skip_data(req);
		}
		break;
	}
	case READ_6:
	case READ_10:
	case READ_16:
	{
		loff_t offset;
		u32 length;

		if (!(req_hdr->flags & ISCSI_CMD_FINAL) || req->pdu.datasize) {
			/* unexpected unsolicited data */
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->scb[0]);
			create_sense_rsp(req, ABORTED_COMMAND, 0xc, 0xc);
			cmnd_skip_data(req);
			break;
		}

		set_offset_and_length(req->lun, req_hdr->scb, &offset, &length);
		req->tio = tio_alloc(get_pgcnt(length, offset));
		tio_set(req->tio, length, offset);
		break;
	}
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
	case WRITE_VERIFY:
	{
		struct iscsi_sess_param *param = &conn->session->param;
		loff_t offset;
		u32 length;

		req->r2t_length = be32_to_cpu(req_hdr->data_length) - req->pdu.datasize;
		req->is_unsolicited_data = !(req_hdr->flags & ISCSI_CMD_FINAL);
		req->target_task_tag = get_next_ttt(conn->session);

		if (LUReadonly(req->lun)) {
			create_sense_rsp(req, DATA_PROTECT, 0x27, 0x0);
			cmnd_skip_data(req);
			break;
		}

		if (!param->immediate_data && req->pdu.datasize)
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->scb[0]);

		if (param->initial_r2t && !(req_hdr->flags & ISCSI_CMD_FINAL))
			eprintk("%x %x\n", cmnd_itt(req), req_hdr->scb[0]);

		if (req_hdr->scb[0] == WRITE_VERIFY && req_hdr->scb[1] & 0x02)
			eprintk("Verification is ignored %x\n", cmnd_itt(req));

		set_offset_and_length(req->lun, req_hdr->scb, &offset, &length);
		if (cmnd_write_size(req) != length)
			eprintk("%x %u %u\n", cmnd_itt(req), cmnd_write_size(req), length);

		req->tio = tio_alloc(get_pgcnt(length, offset));
		tio_set(req->tio, length, offset);

		if (req->pdu.datasize) {
			if (cmnd_recv_pdu(conn, req->tio, 0, req->pdu.datasize) < 0)
				assert(0);
		}
		break;
	}
	error:
	default:
		eprintk("Unsupported %x\n", req_hdr->scb[0]);
		create_sense_rsp(req, ILLEGAL_REQUEST, 0x20, 0x0);
		cmnd_skip_data(req);
		break;
	}

out:
	return;
}

static void data_out_start(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	struct iscsi_data_out_hdr *req = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
	struct iscsi_cmnd *scsi_cmnd = NULL;
	u32 offset = be32_to_cpu(req->buffer_offset);

	update_stat_sn(cmnd);

	cmnd->req = scsi_cmnd = cmnd_find_hash(conn->session, req->itt, req->ttt);
	if (!scsi_cmnd) {
		eprintk("unable to find scsi task %x %x\n",
			cmnd_itt(cmnd), cmnd_ttt(cmnd));
		goto skip_data;
	}

	if (scsi_cmnd->r2t_length < cmnd->pdu.datasize) {
		eprintk("invalid data len %x %u %u\n",
			cmnd_itt(scsi_cmnd), cmnd->pdu.datasize, scsi_cmnd->r2t_length);
		goto skip_data;
	}

	if (scsi_cmnd->r2t_length + offset != cmnd_write_size(scsi_cmnd)) {
		eprintk("%x %u %u %u\n", cmnd_itt(scsi_cmnd), scsi_cmnd->r2t_length,
			offset,	cmnd_write_size(scsi_cmnd));
		goto skip_data;
	}

	scsi_cmnd->r2t_length -= cmnd->pdu.datasize;

	if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		/* unsolicited burst data */
		if (scsi_cmnd->pdu.bhs.flags & ISCSI_FLG_FINAL) {
			eprintk("unexpected data from %x %x\n",
				cmnd_itt(cmnd), cmnd_ttt(cmnd));
			goto skip_data;
		}
	}

	dprintk(D_WRITE, "%u %p %p %p %u %u\n", req->ttt, cmnd, scsi_cmnd,
		scsi_cmnd->tio, offset, cmnd->pdu.datasize);

	if (cmnd_recv_pdu(conn, scsi_cmnd->tio, offset, cmnd->pdu.datasize) < 0)
		goto skip_data;
	return;

skip_data:
	cmnd->pdu.bhs.opcode = ISCSI_OP_DATA_REJECT;
	cmnd_skip_pdu(cmnd);
	return;
}

static void data_out_end(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	struct iscsi_data_out_hdr *req = (struct iscsi_data_out_hdr *) &cmnd->pdu.bhs;
	struct iscsi_cmnd *scsi_cmnd;
	u32 offset;

	assert(cmnd);
	scsi_cmnd = cmnd->req;
	assert(scsi_cmnd);

	if (conn->read_overflow) {
		eprintk("%x %u\n", cmnd_itt(cmnd), conn->read_overflow);
		assert(scsi_cmnd->tio);
		offset = be32_to_cpu(req->buffer_offset);
		offset += cmnd->pdu.datasize - conn->read_overflow;
		if (cmnd_recv_pdu(conn, scsi_cmnd->tio, offset, conn->read_overflow) < 0)
			assert(0);
		return;
	}

	if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		if (req->flags & ISCSI_FLG_FINAL) {
			scsi_cmnd->is_unsolicited_data = 0;
			if (!cmnd_pending(scsi_cmnd))
				scsi_cmnd_exec(scsi_cmnd);
		}
	} else {
		/* TODO : proper error handling */
		if (!(req->flags & ISCSI_FLG_FINAL) && scsi_cmnd->r2t_length == 0)
			eprintk("initiator error %x\n", cmnd_itt(scsi_cmnd));

		if (!(req->flags & ISCSI_FLG_FINAL))
			goto out;

		scsi_cmnd->outstanding_r2t--;

		if (scsi_cmnd->r2t_length == 0)
			assert(list_empty(&scsi_cmnd->pdu_list));

		scsi_cmnd_exec(scsi_cmnd);
	}

out:
	iscsi_cmnd_remove(cmnd);
	return;
}

static int __cmnd_abort(struct iscsi_cmnd *cmnd)
{
	if (cmnd_waitio(cmnd))
		return -ISCSI_RESPONSE_UNKNOWN_TASK;

	if (cmnd->conn->read_cmnd != cmnd)
		cmnd_release(cmnd, 1);
	else if (cmnd_rxstart(cmnd))
		set_cmnd_tmfabort(cmnd);
	else
		return -ISCSI_RESPONSE_UNKNOWN_TASK;

	return 0;
}

static int cmnd_abort(struct iscsi_session *session, u32 itt)
{
	struct iscsi_cmnd *cmnd;
	int err =  -ISCSI_RESPONSE_UNKNOWN_TASK;

	if ((cmnd = cmnd_find_hash(session, itt, ISCSI_RESERVED_TAG))) {
		eprintk("%x %x %x %u %u %u %u\n", cmnd_itt(cmnd), cmnd_opcode(cmnd),
			cmnd->r2t_length, cmnd_scsicode(cmnd),
			cmnd_write_size(cmnd), cmnd->is_unsolicited_data,
			cmnd->outstanding_r2t);
		err = __cmnd_abort(cmnd);
	}

	return err;
}

static int target_reset(struct iscsi_cmnd *req, u32 lun, int all)
{
	struct iscsi_target *target = req->conn->session->target;
	struct iscsi_session *session;
	struct iscsi_conn *conn;
	struct iscsi_cmnd *cmnd, *tmp;
	struct iet_volume *volume;

	list_for_each_entry(session, &target->session_list, list) {
		list_for_each_entry(conn, &session->conn_list, list) {
			list_for_each_entry_safe(cmnd, tmp, &conn->pdu_list, conn_list) {
				if (cmnd == req)
					continue;

				if (all)
					__cmnd_abort(cmnd);
				else if (translate_lun(cmnd_hdr(cmnd)->lun) == lun)
					__cmnd_abort(cmnd);
			}
		}
	}

	list_for_each_entry(volume, &target->volumes, list) {
		if (all || volume->lun == lun) {
			/* force release */
			volume_release(volume, 0, 1);
			/* power-on, reset, or bus device reset occurred */
			ua_establish_for_all_sessions(target, volume->lun,
						      0x29, 0x0);
		}
	}

	return 0;
}

static void task_set_abort(struct iscsi_cmnd *req)
{
	struct iscsi_session *session = req->conn->session;
	struct iscsi_conn *conn;
	struct iscsi_cmnd *cmnd, *tmp;

	list_for_each_entry(conn, &session->conn_list, list) {
		list_for_each_entry_safe(cmnd, tmp, &conn->pdu_list, conn_list) {
			if (cmnd != req)
				__cmnd_abort(cmnd);
		}
	}
}

static inline char *tmf_desc(int fun)
{
	static char *tmf_desc[] = {
		"Unknown Function",
		"Abort Task",
		"Abort Task Set",
		"Clear ACA",
		"Clear Task Set",
		"Logical Unit Reset",
		"Target Warm Reset",
		"Target Cold Reset",
		"Task Reassign",
        };

	if ((fun < ISCSI_FUNCTION_ABORT_TASK) ||
				(fun > ISCSI_FUNCTION_TASK_REASSIGN))
		fun = 0;

	return tmf_desc[fun];
}

static inline char *rsp_desc(int rsp)
{
	static char *rsp_desc[] = {
		"Function Complete",
		"Unknown Task",
		"Unknown LUN",
		"Task Allegiant",
		"Failover Unsupported",
		"Function Unsupported",
		"No Authorization",
		"Function Rejected",
		"Unknown Response",
	};

	if (((rsp < ISCSI_RESPONSE_FUNCTION_COMPLETE) ||
			(rsp > ISCSI_RESPONSE_NO_AUTHORIZATION)) &&
			(rsp != ISCSI_RESPONSE_FUNCTION_REJECTED))
		rsp = 8;
	else if (rsp == ISCSI_RESPONSE_FUNCTION_REJECTED)
		rsp = 7;

	return rsp_desc[rsp];
}

static void execute_task_management(struct iscsi_cmnd *req)
{
	struct iscsi_conn *conn = req->conn;
	struct iscsi_session *session = conn->session;
	struct iscsi_target *target = session->target;
	struct iscsi_cmnd *rsp;
	struct iscsi_task_mgt_hdr *req_hdr = (struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
	struct iscsi_task_rsp_hdr *rsp_hdr;
	u32 lun;
	int err, function = req_hdr->function & ISCSI_FUNCTION_MASK;

	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);
	rsp_hdr = (struct iscsi_task_rsp_hdr *)&rsp->pdu.bhs;

	rsp_hdr->opcode = ISCSI_OP_SCSI_TASK_MGT_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->itt = req_hdr->itt;
	rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_COMPLETE;

	switch (function) {
	case ISCSI_FUNCTION_ABORT_TASK:
	case ISCSI_FUNCTION_ABORT_TASK_SET:
	case ISCSI_FUNCTION_CLEAR_ACA:
	case ISCSI_FUNCTION_CLEAR_TASK_SET:
	case ISCSI_FUNCTION_LOGICAL_UNIT_RESET:
		lun = translate_lun(req_hdr->lun);
		if (!volume_lookup(target, lun)) {
			rsp_hdr->response = ISCSI_RESPONSE_UNKNOWN_LUN;
			goto out;
		}
	}

	switch (function) {
	case ISCSI_FUNCTION_ABORT_TASK:
		if ((err = cmnd_abort(conn->session, req_hdr->rtt)) < 0)
			rsp_hdr->response = -err;
		break;
	case ISCSI_FUNCTION_ABORT_TASK_SET:
		task_set_abort(req);
		break;
	case ISCSI_FUNCTION_CLEAR_ACA:
		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_UNSUPPORTED;
		break;
	case ISCSI_FUNCTION_CLEAR_TASK_SET:
		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_UNSUPPORTED;
		break;
	case ISCSI_FUNCTION_LOGICAL_UNIT_RESET:
		target_reset(req, translate_lun(req_hdr->lun), 0);
		break;
	case ISCSI_FUNCTION_TARGET_WARM_RESET:
	case ISCSI_FUNCTION_TARGET_COLD_RESET:
		target_reset(req, 0, 1);
		if (function == ISCSI_FUNCTION_TARGET_COLD_RESET)
			set_cmnd_close(rsp);
		break;
	case ISCSI_FUNCTION_TASK_REASSIGN:
		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_UNSUPPORTED;
		break;
	default:
		rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_REJECTED;
		break;
	}
out:
	iprintk("%s (%02x) issued on tid:%d lun:%d by sid:%llu (%s)\n",
				tmf_desc(function), function, target->tid,
				translate_lun(req_hdr->lun), session->sid,
				rsp_desc(rsp_hdr->response));

	iscsi_cmnd_init_write(rsp);
}

static void nop_hdr_setup(struct iscsi_hdr *hdr, u8 opcode, __be32 itt,
			  __be32 ttt)
{
	hdr->opcode = opcode;
	hdr->flags = ISCSI_FLG_FINAL;
	hdr->itt = itt;
	hdr->ttt = ttt;
}

static void nop_out_exec(struct iscsi_cmnd *req)
{
	struct iscsi_cmnd *rsp;

	if (cmnd_itt(req) != cpu_to_be32(ISCSI_RESERVED_TAG)) {
		rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);

		nop_hdr_setup(&rsp->pdu.bhs, ISCSI_OP_NOP_IN, req->pdu.bhs.itt,
			      cpu_to_be32(ISCSI_RESERVED_TAG));

		if (req->pdu.datasize)
			assert(req->tio);
		else
			assert(!req->tio);

		if (req->tio) {
			tio_get(req->tio);
			rsp->tio = req->tio;
		}

		assert(get_pgcnt(req->pdu.datasize, 0) < ISCSI_CONN_IOV_MAX);
		rsp->pdu.datasize = req->pdu.datasize;
		iscsi_cmnd_init_write(rsp);
	} else {
		if (req->req) {
			dprintk(D_GENERIC, "releasing NOP-Out %p, ttt %x; "
				"removing NOP-In %p, ttt %x\n", req->req,
				cmnd_ttt(req->req), req, cmnd_ttt(req));
			cmnd_release(req->req, 0);
		}
		iscsi_cmnd_remove(req);
	}
}

static void nop_in_timeout(unsigned long data)
{
	struct iscsi_cmnd *req = (struct iscsi_cmnd *)data;

	printk(KERN_INFO "NOP-In ping timed out - closing sid:cid %llu:%u\n",
	       req->conn->session->sid, req->conn->cid);
	clear_cmnd_timer_active(req);
	conn_close(req->conn);
}

/* create a fake NOP-Out req and treat the NOP-In as our rsp to it */
void send_nop_in(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *req = cmnd_alloc(conn, 1);
	struct iscsi_cmnd *rsp = iscsi_cmnd_create_rsp_cmnd(req, 0);

	req->target_task_tag = get_next_ttt(conn->session);


	nop_hdr_setup(&req->pdu.bhs, ISCSI_OP_NOP_OUT,
		      cpu_to_be32(ISCSI_RESERVED_TAG), req->target_task_tag);
	nop_hdr_setup(&rsp->pdu.bhs, ISCSI_OP_NOP_IN,
		      cpu_to_be32(ISCSI_RESERVED_TAG), req->target_task_tag);

	dprintk(D_GENERIC, "NOP-Out: %p, ttt %x, timer %p; "
		"NOP-In: %p, ttt %x;\n", req, cmnd_ttt(req), &req->timer, rsp,
		cmnd_ttt(rsp));

	init_timer(&req->timer);
	req->timer.data = (unsigned long)req;
	req->timer.function = nop_in_timeout;

	if (cmnd_insert_hash_ttt(req, req->target_task_tag)) {
		eprintk("%s\n",
			"failed to insert fake NOP-Out into hash table");
		cmnd_release(rsp, 0);
		cmnd_release(req, 0);
	} else
		iscsi_cmnd_init_write(rsp);
}

static void nop_in_tx_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	u32 t;

	if (cmnd->pdu.bhs.ttt == cpu_to_be32(ISCSI_RESERVED_TAG))
		return;

	/*
	 * NOP-In ping issued by the target.
	 * FIXME: Sanitize the NOP timeout earlier, during configuration
	 */
	t = conn->session->target->trgt_param.nop_timeout;

	if (!t || t > conn->session->target->trgt_param.nop_interval) {
		eprintk("Adjusting NOPTimeout of tid %u from %u to %u "
			"(== NOPInterval)\n", conn->session->target->tid,
			t,
			conn->session->target->trgt_param.nop_interval);
		t = conn->session->target->trgt_param.nop_interval;
		conn->session->target->trgt_param.nop_timeout = t;
	}

	dprintk(D_GENERIC, "NOP-In %p, %x: timer %p\n",	cmnd, cmnd_ttt(cmnd),
		&cmnd->req->timer);

	set_cmnd_timer_active(cmnd->req);
	mod_timer(&cmnd->req->timer, jiffies + HZ * t);
}

static void logout_exec(struct iscsi_cmnd *req)
{
	struct iscsi_logout_req_hdr *req_hdr;
	struct iscsi_cmnd *rsp;
	struct iscsi_logout_rsp_hdr *rsp_hdr;

	req_hdr = (struct iscsi_logout_req_hdr *)&req->pdu.bhs;
	rsp = iscsi_cmnd_create_rsp_cmnd(req, 1);
	rsp_hdr = (struct iscsi_logout_rsp_hdr *)&rsp->pdu.bhs;
	rsp_hdr->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp_hdr->flags = ISCSI_FLG_FINAL;
	rsp_hdr->itt = req_hdr->itt;
	set_cmnd_close(rsp);
	iscsi_cmnd_init_write(rsp);
}

static void iscsi_cmnd_exec(struct iscsi_cmnd *cmnd)
{
	dprintk(D_GENERIC, "%p,%x,%u\n", cmnd, cmnd_opcode(cmnd), cmnd->pdu.bhs.sn);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_OUT:
		nop_out_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_CMD:
		scsi_cmnd_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		execute_task_management(cmnd);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		logout_exec(cmnd);
		break;
	case ISCSI_OP_SCSI_REJECT:
		iscsi_cmnd_init_write(get_rsp_cmnd(cmnd));
		break;
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_SNACK_CMD:
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		break;
	}
}

static void __cmnd_send_pdu(struct iscsi_conn *conn, struct tio *tio, u32 offset, u32 size)
{
	dprintk(D_GENERIC, "%p %u,%u\n", tio, offset, size);
	offset += tio->offset;

	assert(offset <= tio->offset + tio->size);
	assert(offset + size <= tio->offset + tio->size);

	conn->write_tcmnd = tio;
	conn->write_offset = offset;
	conn->write_size += size;
}

static void cmnd_send_pdu(struct iscsi_conn *conn, struct iscsi_cmnd *cmnd)
{
	u32 size;
	struct tio *tio;

	if (!cmnd->pdu.datasize)
		return;

	size = (cmnd->pdu.datasize + 3) & -4;
	tio = cmnd->tio;
	assert(tio);
	assert(tio->size == size);
	__cmnd_send_pdu(conn, tio, 0, size);
}

static void set_cork(struct socket *sock, int on)
{
	int opt = on;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	sock->ops->setsockopt(sock, SOL_TCP, TCP_CORK, (void *)&opt, sizeof(opt));
	set_fs(oldfs);
}

void cmnd_release(struct iscsi_cmnd *cmnd, int force)
{
	struct iscsi_cmnd *req, *rsp;
	int is_last = 0;

	if (!cmnd)
		return;

/* 	eprintk("%x %lx %d\n", cmnd_opcode(cmnd), cmnd->flags, force); */

	req = cmnd->req;
	is_last = cmnd_final(cmnd);

	if (force) {
		while (!list_empty(&cmnd->pdu_list)) {
			rsp = list_entry(cmnd->pdu_list.next, struct iscsi_cmnd, pdu_list);
			list_del_init(&rsp->list);
			list_del(&rsp->pdu_list);
			iscsi_cmnd_remove(rsp);
		}
		list_del_init(&cmnd->list);
	} else
		if (cmnd_queued(cmnd))
			iscsi_scsi_dequeuecmnd(cmnd);

	if (cmnd_hashed(cmnd))
		cmnd_remove_hash(cmnd);

	if (cmnd_lunit(cmnd)) {
		assert(cmnd->lun);
		volume_put(cmnd->lun);
	}

	list_del_init(&cmnd->pdu_list);
	iscsi_cmnd_remove(cmnd);

	if (is_last) {
		assert(!force);
		assert(req);
		cmnd_release(req, 0);
	}

	return;
}

void cmnd_tx_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iovec *iop;

	dprintk(D_GENERIC, "%p:%x\n", cmnd, cmnd_opcode(cmnd));
	assert(cmnd);
	iscsi_cmnd_set_length(&cmnd->pdu);

	set_cork(conn->sock, 1);

	conn->write_iop = iop = conn->write_iov;
	iop->iov_base = &cmnd->pdu.bhs;
	iop->iov_len = sizeof(cmnd->pdu.bhs);
	iop++;
	conn->write_size = sizeof(cmnd->pdu.bhs);

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_IN:
		if (cmnd->pdu.bhs.itt == ISCSI_RESERVED_TAG) {
			/* NOP-In ping generated by us. Don't advance StatSN. */
			cmnd_set_sn(cmnd, 0);
			cmnd_set_sn(cmnd->req, 0);
			cmnd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn);
			cmnd->req->pdu.bhs.sn = cpu_to_be32(conn->stat_sn);
		} else
			cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_RSP:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_TEXT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_DATA_IN:
	{
		struct iscsi_data_in_hdr *rsp = (struct iscsi_data_in_hdr *)&cmnd->pdu.bhs;
		u32 offset;

		cmnd_set_sn(cmnd, (rsp->flags & ISCSI_FLG_FINAL) ? 1 : 0);
		offset = rsp->buffer_offset;
		rsp->buffer_offset = cpu_to_be32(offset);
		__cmnd_send_pdu(conn, cmnd->tio, offset, cmnd->pdu.datasize);
		break;
	}
	case ISCSI_OP_LOGOUT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_R2T:
		cmnd_set_sn(cmnd, 0);
		cmnd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn);
		break;
	case ISCSI_OP_ASYNC_MSG:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_REJECT:
		cmnd_set_sn(cmnd, 1);
		cmnd_send_pdu(conn, cmnd);
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		break;
	}

	iop->iov_len = 0;
	// move this?
	conn->write_size = (conn->write_size + 3) & -4;
	iscsi_dump_pdu(&cmnd->pdu);
}

void cmnd_tx_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	dprintk(D_GENERIC, "%p:%x\n", cmnd, cmnd_opcode(cmnd));
	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_IN:
		nop_in_tx_end(cmnd);
		break;
	case ISCSI_OP_SCSI_RSP:
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_R2T:
	case ISCSI_OP_ASYNC_MSG:
	case ISCSI_OP_REJECT:
	case ISCSI_OP_SCSI_DATA_IN:
	case ISCSI_OP_LOGOUT_RSP:
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		assert(0);
		break;
	}

	if (cmnd_close(cmnd))
		conn_close(conn);

	list_del_init(&cmnd->list);
	set_cork(cmnd->conn->sock, 0);
}

/**
 * Push the command for execution.
 * This functions reorders the commands.
 * Called from the read thread.
 *
 * iscsi_session_push_cmnd -
 * @cmnd: ptr to command
 */

static void iscsi_session_push_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct list_head *entry;
	u32 cmd_sn;

	dprintk(D_GENERIC, "%p:%x %u,%u\n",
		cmnd, cmnd_opcode(cmnd), cmnd->pdu.bhs.sn, session->exp_cmd_sn);

	if (cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) {
		iscsi_cmnd_exec(cmnd);
		return;
	}

	cmd_sn = cmnd->pdu.bhs.sn;
	if (cmd_sn == session->exp_cmd_sn) {
		while (1) {
			session->exp_cmd_sn = ++cmd_sn;
			iscsi_cmnd_exec(cmnd);

			if (list_empty(&session->pending_list))
				break;
			cmnd = list_entry(session->pending_list.next, struct iscsi_cmnd, list);
			if (cmnd->pdu.bhs.sn != cmd_sn)
				break;
/* 			eprintk("find out-of-order %x %u %u\n", */
/* 				cmnd_itt(cmnd), cmd_sn, cmnd->pdu.bhs.sn); */
			list_del_init(&cmnd->list);
			clear_cmnd_pending(cmnd);
		}
	} else {
/* 		eprintk("out-of-order %x %u %u\n", */
/* 			cmnd_itt(cmnd), cmd_sn, session->exp_cmd_sn); */

		set_cmnd_pending(cmnd);
		if (before(cmd_sn, session->exp_cmd_sn)) /* close the conn */
			eprintk("unexpected cmd_sn (%u,%u)\n", cmd_sn, session->exp_cmd_sn);

		if (after(cmd_sn, session->exp_cmd_sn + session->max_queued_cmnds))
			eprintk("too large cmd_sn (%u,%u)\n", cmd_sn, session->exp_cmd_sn);

		list_for_each(entry, &session->pending_list) {
			struct iscsi_cmnd *tmp = list_entry(entry, struct iscsi_cmnd, list);
			if (before(cmd_sn, tmp->pdu.bhs.sn))
				break;
		}

		assert(list_empty(&cmnd->list));

		list_add_tail(&cmnd->list, entry);
	}
}

static int check_segment_length(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_sess_param *param = &conn->session->param;

	if (cmnd->pdu.datasize > param->max_recv_data_length) {
		eprintk("data too long %x %u %u\n", cmnd_itt(cmnd),
			cmnd->pdu.datasize, param->max_recv_data_length);

		if (get_pgcnt(cmnd->pdu.datasize, 0) > ISCSI_CONN_IOV_MAX) {
			conn_close(conn);
			return -EINVAL;
		}
	}

	return 0;
}

void cmnd_rx_start(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	int err = 0;

	iscsi_dump_pdu(&cmnd->pdu);

	set_cmnd_rxstart(cmnd);
	if (check_segment_length(cmnd) < 0)
		return;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_OUT:
		err = nop_out_start(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_CMD:
		if (!(err = cmnd_insert_hash(cmnd)))
			scsi_cmnd_start(conn, cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		err = cmnd_insert_hash(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		data_out_start(conn, cmnd);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		err = cmnd_insert_hash(cmnd);
		break;
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_SNACK_CMD:
		err = -ISCSI_REASON_UNSUPPORTED_COMMAND;
		break;
	default:
		err = -ISCSI_REASON_UNSUPPORTED_COMMAND;
		break;
	}

	if (err < 0) {
		eprintk("%x %x %d\n", cmnd_opcode(cmnd), cmnd_itt(cmnd), err);
		iscsi_cmnd_reject(cmnd, -err);
	}
}

void cmnd_rx_end(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	if (cmnd_tmfabort(cmnd)) {
		cmnd_release(cmnd, 1);
		return;
	}

	dprintk(D_GENERIC, "%p:%x\n", cmnd, cmnd_opcode(cmnd));
	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_REJECT:
	case ISCSI_OP_NOP_OUT:
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_LOGOUT_CMD:
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		data_out_end(conn, cmnd);
		break;
	case ISCSI_OP_SNACK_CMD:
		break;
	case ISCSI_OP_PDU_REJECT:
		iscsi_cmnd_init_write(get_rsp_cmnd(cmnd));
		break;
	case ISCSI_OP_DATA_REJECT:
		cmnd_release(cmnd, 0);
		break;
	default:
		eprintk("unexpected cmnd op %x\n", cmnd_opcode(cmnd));
		BUG();
		break;
	}
}

static void iscsi_exit(void)
{
	wthread_module_exit();

	unregister_chrdev(ctr_major, ctr_name);

	iet_procfs_exit();

	event_exit();

	tio_exit();

	iotype_exit();

	ua_exit();

	if (iscsi_cmnd_cache)
		kmem_cache_destroy(iscsi_cmnd_cache);
}

static int iscsi_init(void)
{
	int err = -ENOMEM;

	printk("iSCSI Enterprise Target Software - version %s\n", IET_VERSION_STRING);

	if ((ctr_major = register_chrdev(0, ctr_name, &ctr_fops)) < 0) {
		eprintk("failed to register the control device %d\n", ctr_major);
		return ctr_major;
	}

	if ((err = iet_procfs_init()) < 0)
		goto err;

	if ((err = event_init()) < 0)
		goto err;

	iscsi_cmnd_cache = KMEM_CACHE(iscsi_cmnd, 0);
	if (!iscsi_cmnd_cache)
		goto err;

	err = ua_init();
	if (err < 0)
		goto err;

	if ((err = tio_init()) < 0)
		goto err;

	if ((err = iotype_init()) < 0)
		goto err;

	if ((err = wthread_module_init()) < 0)
		goto err;

	return 0;

err:
	iscsi_exit();
	return err;
}

module_param(worker_thread_pool_size, ulong, S_IRUGO);
MODULE_PARM_DESC(worker_thread_pool_size,
		 "Size of the worker thread pool "
		 "(0 = dedicated threads per target (default))");

module_param(debug_enable_flags, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug_enable_flags,
		 "debug bitmask, low bits (0 ... 8) used, see iscsi_dbg.h");

module_init(iscsi_init);
module_exit(iscsi_exit);

MODULE_VERSION(IET_VERSION_STRING);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("iSCSI Enterprise Target");
MODULE_AUTHOR("IET development team <iscsitarget-devel@lists.sourceforge.net>");
