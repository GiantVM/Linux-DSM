#ifndef ARCH_X86_KVM_XBZRLE_H
#define ARCH_X86_KVM_XBZRLE_H
/*
 * Copyright (C) 2018, Trusted Cloud Group, Shanghai Jiao Tong University.
 *
 * Authors:
 *  Jin Zhang 	    <jzhang3002@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
int xbzrle_encode_buffer(const uint8_t *old_buf, const uint8_t *new_buf, int slen,
	uint8_t *dst, int dlen);

int xbzrle_decode_buffer(const uint8_t *src, int slen, uint8_t *dst, int dlen);

#endif /* ARCH_X86_KVM_XBZRLE_H */
