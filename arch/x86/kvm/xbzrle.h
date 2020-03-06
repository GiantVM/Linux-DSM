#ifndef ARCH_X86_KVM_XBZRLE_H
#define ARCH_X86_KVM_XBZRLE_H

int xbzrle_encode_buffer(const uint8_t *old_buf, const uint8_t *new_buf, int slen,
	uint8_t *dst, int dlen);

int xbzrle_decode_buffer(const uint8_t *src, int slen, uint8_t *dst, int dlen);

#endif /* ARCH_X86_KVM_XBZRLE_H */
