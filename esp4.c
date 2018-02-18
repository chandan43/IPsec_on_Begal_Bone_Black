#define pr_fmt(fmt) "IPsec: " fmt

#include <linux/module.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/in6.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/udp.h>

static int esp_output(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist *sg;
	struct sk_buff *trailer;
	void *tmp;
	u8 *iv;
	u8 *tail;
	int blksize;
	int clen;
	int alen;
	int plen;
	int ivlen;
	int tfclen;
	int nfrags;
	int assoclen;
	int seqhilen;
	__be32 *seqhi;
	__be64 seqno;
	
	/* skb is pure payload to encrypt */

	aead = x->data;
	alen = crypto_aead_authsize(aead);
	ivlen = crypto_aead_ivsize(aead);
	
	tfclen = 0;
	/*Traffic Flow Confidentiality (TFC) Padding : rfc 4303 : https://doc.hcc-embedded.com/display/INICHEIPSECANDIKE/TFC+Padding*/
	if (x->tfcpad) {
		struct xfrm_dst *dst = (struct xfrm_dst *)skb_dst(skb);
		u32 padto;

		padto = min(x->tfcpad, esp4_get_mtu(x, dst->child_mtu_cached));
		if (skb->len < padto)
			tfclen = padto - skb->len;
	}
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	clen = ALIGN(skb->len + 2 + tfclen, blksize); // TODO
	plen = clen - skb->len - tfclen; //TODO

	err = skb_cow_data(skb, tfclen + plen + alen, &trailer);
	
	if (err < 0)
		goto error;
	nfrags = err;

	assoclen = sizeof(*esph);
	seqhilen = 0;
	
	if (x->props.flags & XFRM_STATE_ESN) {
		seqhilen += sizeof(__be32);
		assoclen += seqhilen;
	}

	tmp = esp_alloc_tmp(aead, nfrags, seqhilen);
	if (!tmp) {
		err = -ENOMEM;
		goto error;
	}

	seqhi = esp_tmp_seqhi(tmp);
	iv = esp_tmp_iv(aead, tmp, seqhilen);
	req = esp_tmp_req(aead, iv);
	sg = esp_req_sg(aead, req);

	/* Fill padding... */
	tail = skb_tail_pointer(trailer);
	if (tfclen) {
		memset(tail, 0, tfclen);
		tail += tfclen;
	}
	do {
		int i;
		for (i = 0; i < plen - 2; i++)
			tail[i] = i + 1;
	} while (0);
	###STOP## rfc 	
}

/**
 *	skb_copy_bits - copy bits from skb to kernel buffer
 *	@skb: source skb
 *	@offset: offset in source
 *	@to: destination buffer
 *	@len: number of bytes to copy
 *
 *	Copy the specified number of bytes from the source skb to the
 *	destination buffer.
 *
 *	CAUTION ! :
 *		If its prototype is ever changed,
 *		check arch/{*}/net/{*}.S files,
 *		since it is called from BPF assembly code.
 */
/**
 *	pskb_trim_unique - remove end from a paged unique (not cloned) buffer
 *	@skb: buffer to alter
 *	@len: new length
 *
 *	This is identical to pskb_trim except that the caller knows that
 *	the skb is not cloned so we should never get an error due to out-
 *	of-memory.
 */
 /* Removing data from the front of the buffer
    The skb_pull() function logicially removes data from 
    the start of a buffer returning the space to the headroom.  It 
    increments the skb­>data  pointer and decrements the value of skb­>len
    effectively removing data from the head of a buffer and returning it 
    to the headroom.  It returns a pointer to the new start of data
 */
static int esp_input_done2(struct sk_buff *skb, int err)
{
	const struct iphdr *iph;
	struct xfrm_state *x = xfrm_input_state(skb);
	struct crypto_aead *aead = x->data;
	int alen = crypto_aead_authsize(aead);
	int hlen = sizeof(struct ip_esp_hdr) + crypto_aead_ivsize(aead);
	int elen = skb->len - hlen;
	int ihl;
	u8 nexthdr[2];
	int padlen;

	kfree(ESP_SKB_CB(skb)->tmp);

	if (unlikely(err))
		goto out;

	if (skb_copy_bits(skb, skb->len-alen-2, nexthdr, 2))
		BUG();
	
	err = -EINVAL;
	padlen = nexthdr[0];
	if (padlen + 2 + alen >= elen)
		goto out;

	/* ... check padding bits here. Silly. :-) */

	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;

	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;
		struct udphdr *uh = (void *)(skb_network_header(skb) + ihl);

		/*
		 * 1) if the NAT-T peer's IP or port changed then
		 *    advertize the change to the keying daemon.
		 *    This is an inbound SA, so just compare
		 *    SRC ports.
		 */
		if (iph->saddr != x->props.saddr.a4 ||
		    uh->source != encap->encap_sport) {
			xfrm_address_t ipaddr;

			ipaddr.a4 = iph->saddr;
			km_new_mapping(x, &ipaddr, uh->source);

			/* XXX: perhaps add an extra
			 * policy check here, to see
			 * if we should allow or
			 * reject a packet from a
			 * different source
			 * address/port.
			 */
		}

		/*
		 * 2) ignore UDP/TCP checksums in case
		 *    of NAT-T in Transport Mode, or
		 *    perform other post-processing fixes
		 *    as per draft-ietf-ipsec-udp-encaps-06,
		 *    section 3.1.2
		 */
		if (x->props.mode == XFRM_MODE_TRANSPORT)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	
	pskb_trim(skb, skb->len - alen - padlen - 2);
	__skb_pull(skb, hlen);
	if (x->props.mode == XFRM_MODE_TUNNEL)
		skb_reset_transport_header(skb);
	else
		skb_set_transport_header(skb, -ihl);

	err = nexthdr[1];

	/* RFC4303: Drop dummy packets without any error */
	if (err == IPPROTO_NONE)
		err = -EINVAL;

out:
	return err;
}
static void esp_input_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	xfrm_input_resume(skb, esp_input_done2(skb, err)); //TODO
}

static void esp_input_restore_header(struct sk_buff *skb)
{
	esp_restore_header(skb, 0); //TODO
	__skb_pull(skb, 4);
}
static void esp_input_done_esn(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	esp_input_restore_header(skb);
	esp_input_done(base, err);
}
/**
 *	struct aead_request - AEAD request
 *	@base: Common attributes for async crypto requests
 *	@assoclen: Length in bytes of associated data for authentication
 *	@cryptlen: Length of data to be encrypted or decrypted
 *	@iv: Initialisation vector
 *	@assoc: Associated data
 *	@src: Source data
 *	@dst: Destination data
 *	@__ctx: Start of private context data
 */

/*
  The job of pskb_may_pull is to make sure that the area pointed to by
  skb->data contains a block of
  data at least as big as the IP header, since each IP packet (fragments
  included) must include a complete IP
  header.When we receive a packet , the kernel will call the pkb_may_pull(),
*/

/*
   Make sure that the data buffers attached to a socket buffer are writable. 
   If they are not, private copies are made of the data buffers and the socket 
   buffer is set to use these instead. If tailbits is given, make sure that there 
   is space to write tailbits bytes of data beyond current end of socket buffer.
   trailer will be set to point to the skb in which this space begins.
   The number of scatterlist elements required to completely map the COW'd 
   and extended socket buffer will be returned. 
*/

/*
 * Allocate an AEAD request structure with extra space for SG and IV.
 *
 * For alignment considerations the IV is placed at the front, followed
 * by the request and finally the SG list.
 *
 * TODO: Use spare space in skb for this where possible.
 */
/**
 * sg_init_table - Initialize SG table
 * @sgl:	   The SG table
 * @nents:	   Number of entries in table
 *
 * Notes:
 *   If this is part of a chained sg table, sg_mark_end() should be
 *   used only on the last table part.
 *
 **/
/**
 *	skb_to_sgvec - Fill a scatter-gather list from a socket buffer
 *	@skb: Socket buffer containing the buffers to be mapped
 *	@sg: The scatter-gather list to map into
 *	@offset: The offset into the buffer's contents to start mapping
 *	@len: Length of buffer space to be mapped
 *
 *	Fill the specified scatter-gather list with mappings/pointers into a
 *	region of the buffer space attached to a socket buffer.
 */
 /**
 * aead_request_set_ad - set associated data information
 * @req: request handle
 * @assoclen: number of bytes in associated data
 *
 * Setting the AD information.  This function sets the length of
 * the associated data.
 */
 /**
 * aead_request_set_crypt - set data buffers
 * @req: request handle
 * @src: source scatter / gather list
 * @dst: destination scatter / gather list
 * @cryptlen: number of bytes to process from @src
 * @iv: IV for the cipher operation which must comply with the IV size defined
 *      by crypto_aead_ivsize()
 *
 * Setting the source data and destination data scatter / gather lists which
 * hold the associated data concatenated with the plaintext or ciphertext. See
 * below for the authentication tag.
 *
 * For encryption, the source is treated as the plaintext and the
 * destination is the ciphertext. For a decryption operation, the use is
 * reversed - the source is the ciphertext and the destination is the plaintext.
 *
 * For both src/dst the layout is associated data, plain/cipher text,
 * authentication tag.
 *
 * The content of the AD in the destination buffer after processing
 * will either be untouched, or it will contain a copy of the AD
 * from the source buffer.  In order to ensure that it always has
 * a copy of the AD, the user must copy the AD over either before
 * or after processing.  Of course this is not relevant if the user
 * is doing in-place processing where src == dst.
 *
 * IMPORTANT NOTE AEAD requires an authentication tag (MAC). For decryption,
 *		  the caller must concatenate the ciphertext followed by the
 *		  authentication tag and provide the entire data stream to the
 *		  decryption operation (i.e. the data length used for the
 *		  initialization of the scatterlist and the data length for the
 *		  decryption operation is identical). For encryption, however,
 *		  the authentication tag is created while encrypting the data.
 *		  The destination buffer must hold sufficient space for the
 *		  ciphertext and the authentication tag while the encryption
 *		  invocation must only point to the plaintext data size. The
 *		  following code snippet illustrates the memory usage
 *		  buffer = kmalloc(ptbuflen + (enc ? authsize : 0));
 *		  sg_init_one(&sg, buffer, ptbuflen + (enc ? authsize : 0));
 *		  aead_request_set_crypt(req, &sg, &sg, ptbuflen, iv);
 */
 /**
 * crypto_aead_decrypt() - decrypt ciphertext
 * @req: reference to the ablkcipher_request handle that holds all information
 *	 needed to perform the cipher operation
 *
 * Decrypt ciphertext data using the aead_request handle. That data structure
 * and how it is filled with data is discussed with the aead_request_*
 * functions.
 *
 * IMPORTANT NOTE The caller must concatenate the ciphertext followed by the
 *		  authentication data / tag. That authentication data / tag
 *		  must have the size defined by the crypto_aead_setauthsize
 *		  invocation.
 *
 *
 * Return: 0 if the cipher operation was successful; -EBADMSG: The AEAD
 *	   cipher operation performs the authentication of the data during the
 *	   decryption operation. Therefore, the function returns this error if
 *	   the authentication of the ciphertext was unsuccessful (i.e. the
 *	   integrity of the ciphertext or the associated data was violated);
 *	   < 0 if an error occurred.
 */
/*
 * Note: detecting truncated vs. non-truncated authentication data is very
 * expensive, so we only support truncated data, which is the recommended
 * and common case.
 */
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead = x->data;
	struct aead_request *req;
	struct sk_buff *trailer;
	int ivlen = crypto_aead_ivsize(aead);
	int elen = skb->len - sizeof(*esph) - ivlen;
	int nfrags;
	int assoclen;
	int seqhilen;
	__be32 *seqhi;
	void *tmp;
	u8 *iv;
	struct scatterlist *sg;
	int err = -EINVAL;
	if (!pskb_may_pull(skb, sizeof(*esph) + ivlen)) 
		goto out;
        if (elen <= 0)
		goto out;
         
	err = skb_cow_data(skb, 0, &trailer);  // skb_cow_data — Check that a socket buffer's data buffers are writable 
	if (err < 0)
		goto out;

	nfrags = err;

	assoclen = sizeof(*esph);
	seqhilen = 0;	

	if (x->props.flags & XFRM_STATE_ESN) {
		seqhilen += sizeof(__be32);
		assoclen += seqhilen;
	}
	err = -ENOMEM;
	tmp = esp_alloc_tmp(aead, nfrags, seqhilen); //TODO
	if (!tmp)
		goto out;
	
	ESP_SKB_CB(skb)->tmp = tmp;
	seqhi = esp_tmp_seqhi(tmp);
	iv = esp_tmp_iv(aead, tmp, seqhilen);
	req = esp_tmp_req(aead, iv);
	sg = esp_req_sg(aead, req);

	skb->ip_summed = CHECKSUM_NONE;

	esph = (struct ip_esp_hdr *)skb->data;
	
	/*
	 Setting the callback function that is triggered once the cipher operation 
         completes The callback function is registered with the aead_request handle 
         and must comply with the following template 
        */
	aead_request_set_callback(req, 0, esp_input_done, skb); //set asynchronous callback function 

	/* For ESN we move the header forward by 4 bytes to
	 * accomodate the high bits.  We will move it back after
	 * decryption.
	 */
	if ((x->props.flags & XFRM_STATE_ESN)) {
		esph = (void *)skb_push(skb, 4);
		*seqhi = esph->spi;
		esph->spi = esph->seq_no;
		esph->seq_no = htonl(XFRM_SKB_CB(skb)->seq.input.hi);
		aead_request_set_callback(req, 0, esp_input_done_esn, skb);
	}

	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg, 0, skb->len);

	aead_request_set_crypt(req, sg, sg, elen + ivlen, iv); //set data buffers
	aead_request_set_ad(req, assoclen); // set associated data information

	//decrypt ciphertext
	err = crypto_aead_decrypt(req);
	if (err == -EINPROGRESS)
		goto out;
	if ((x->props.flags & XFRM_STATE_ESN))
		esp_input_restore_header(skb); //TODO

	err = esp_input_done2(skb, err); //TODO	
out:
	return err;	
}

static u32 esp4_get_mtu(struct xfrm_state *x, int mtu)
{
	struct crypto_aead *aead = x->data;
	u32 blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	unsigned int net_adj;
	
	struct crypto_aead *aead = x->data;
	u32 blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	unsigned int net_adj;

	switch (x->props.mode) {
		case XFRM_MODE_TRANSPORT:
		case XFRM_MODE_BEET:
			net_adj = sizeof(struct iphdr);
			break;
		case XFRM_MODE_TUNNEL:
			net_adj = 0;
			break;
		default:
			BUG();
	}

	return ((mtu - x->props.header_len - crypto_aead_authsize(aead) -
		 net_adj) & ~(blksize - 1)) + net_adj - 2;	
}

/*If you have grasped the concept of namespaces you may have 
  at this point an intuitive idea of what a network namespace 
  might offer. Network namespaces provide a brand-new network 
  stack for all the processes within the namespace. That includes
  network interfaces, routing tables and iptables rules.
  https://blogs.igalia.com/dpino/2016/04/10/network-namespaces/
*/
static int esp4_err(struct sk_buff *skb, u32 info)
{
	struct net *net = dev_net(skb->dev);  //Net namespace inlines
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	struct ip_esp_hdr *esph = (struct ip_esp_hdr *)(skb->data+(iph->ihl<<2)); //TODO
	struct xfrm_state *x;
	switch (icmp_hdr(skb)->type) {
	case ICMP_DEST_UNREACH:                    /* Destination Unreachable      */
		if (icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
			return 0;
	case ICMP_REDIRECT:          /* Redirect (change route) */
		break;
	default:
		return 0;
	}	
	x = xfrm_state_lookup(net, skb->mark, (const xfrm_address_t *)&iph->daddr, //TODO
			      esph->spi, IPPROTO_ESP, AF_INET);
	if (!x)
		return 0;
	//TODO
	if (icmp_hdr(skb)->type == ICMP_DEST_UNREACH)
		ipv4_update_pmtu(skb, net, info, 0, 0, IPPROTO_ESP, 0); //used when no socket context is available
	else
		ipv4_redirect(skb, net, 0, 0, IPPROTO_ESP, 0);
	
	xfrm_state_put(x); // xfrm state destroy
	
	return 0;
}

static void esp_destroy(struct xfrm_state *x)
{
	struct crypto_aead *aead = x->data;

	if (!aead)
		return;

	crypto_free_aead(aead);
}
/* Supported aead framework : EX- gcm, gmac : which Can support for 
   encapsulation  and authentication 
*/ 
static int esp_init_aead(struct xfrm_state *x)
{
	char aead_name[CRYPTO_MAX_ALG_NAME];
	struct crypto_aead *aead;
	int err;

	err = -ENAMETOOLONG;
	if (snprintf(aead_name, CRYPTO_MAX_ALG_NAME, "%s(%s)",
		     x->geniv, x->aead->alg_name) >= CRYPTO_MAX_ALG_NAME)
		goto error;

	aead = crypto_alloc_aead(aead_name, 0, 0);
	err = PTR_ERR(aead);
	if (IS_ERR(aead))
		goto error;
	x->data = aead;

	err = crypto_aead_setkey(aead, x->aead->alg_key,
				 (x->aead->alg_key_len + 7) / 8);  //ALIGN 8 byte
	if (err)
		goto error;

	err = crypto_aead_setauthsize(aead, x->aead->alg_icv_len / 8);
	if (err)
		goto error;

error:
	return err;
}
/* 
   Generic structure for encapsulation of optional route information.
   It is reminiscent of sockaddr, but with sa_family replaced
   with attribute type.
 */
 /* ESN: https://tools.ietf.org/html/rfc4304*/
 /* crypto_alloc_aead :  Allocate a cipher handle for an AEAD. The returned struct 
    crypto_aead is the cipher handle that is required for any subsequent 
    API invocation for that AEAD. */
 /* allocated cipher handle in case of success; IS_ERR is true in case of 
    an error, PTR_ERR returns the error code. */
 /* BUG() and BUG_ON(condition) are used as a debugging help when something 
    in the kernel goes terribly wrong. When a BUG_ON() assertion fails, or 
    the code takes a branch with BUG() in it, the kernel will print out the 
    contents of the registers and a stack trace. After that the current process will die. 
 */ 
 /**
 * crypto_aead_setauthsize() - set authentication data size
 * @tfm: cipher handle
 * @authsize: size of the authentication data / tag in bytes
 *
 * Set the authentication data size / tag size. AEAD requires an authentication
 * tag (or MAC) in addition to the associated data.
 *
 * Return: 0 if the setting of the key was successful; < 0 if an error occurred
 */
static int esp_init_authenc(struct xfrm_state *x)
{
	struct crypto_aead *aead;
	struct crypto_authenc_key_param *param;  //enckeylen
	struct rtattr *rta;
	char *key;
	char *p;
	char authenc_name[CRYPTO_MAX_ALG_NAME];
	unsigned int keylen;
	int err;
	
	err = -EINVAL;
	if (!x->ealg)
		goto error;
	err = -ENAMETOOLONG;
	
	if ((x->props.flags & XFRM_STATE_ESN)) {  //Extended Sequence Number
		if (snprintf(authenc_name, CRYPTO_MAX_ALG_NAME,
			     "%s%sauthencesn(%s,%s)%s",
			     x->geniv ?: "", x->geniv ? "(" : "",
			     x->aalg ? x->aalg->alg_name : "digest_null",
			     x->ealg->alg_name,
			     x->geniv ? ")" : "") >= CRYPTO_MAX_ALG_NAME)
			goto error;
	} else {
		if (snprintf(authenc_name, CRYPTO_MAX_ALG_NAME,
			     "%s%sauthenc(%s,%s)%s",
			     x->geniv ?: "", x->geniv ? "(" : "",
			     x->aalg ? x->aalg->alg_name : "digest_null",
			     x->ealg->alg_name,
			     x->geniv ? ")" : "") >= CRYPTO_MAX_ALG_NAME)
			goto error;
	}
	aead = crypto_alloc_aead(authenc_name, 0, 0);
	err = PTR_ERR(aead);
	if (IS_ERR(aead))
		goto error;
	x->data = aead; //private data
	keylen = (x->aalg ? (x->aalg->alg_key_len + 7) / 8 : 0) +
		 (x->ealg->alg_key_len + 7) / 8 + RTA_SPACE(sizeof(*param));
	err = -ENOMEM;
	key = kmalloc(keylen, GFP_KERNEL);
	if (!key)
		goto error;
	p = key;
	/*rtnetlink: macros :https://www.systutorials.com/docs/linux/man/3-rtnetlink/ */
	rta = (void *)p;
	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	rta->rta_len = RTA_LENGTH(sizeof(*param));//returns the length which is required for len bytes of data plus the header.
	param = RTA_DATA(rta); //returns a pointer to the start of this attribute's data. 
	p += RTA_SPACE(sizeof(*param));//returns the amount of space which will be needed in a message with len bytes of data.  
	if (x->aalg) {
		struct xfrm_algo_desc *aalg_desc;

		memcpy(p, x->aalg->alg_key, (x->aalg->alg_key_len + 7) / 8);
		p += (x->aalg->alg_key_len + 7) / 8;

		aalg_desc = xfrm_aalg_get_byname(x->aalg->alg_name, 0); //Get aalg name 
		BUG_ON(!aalg_desc);

		err = -EINVAL;
		if (aalg_desc->uinfo.auth.icv_fullbits / 8 !=
		    crypto_aead_authsize(aead)) {
			pr_info("ESP: %s digestsize %u != %hu\n",
				x->aalg->alg_name,
				crypto_aead_authsize(aead),
				aalg_desc->uinfo.auth.icv_fullbits / 8);
			goto free_key;
		}

		err = crypto_aead_setauthsize(
			aead, x->aalg->alg_trunc_len / 8);
		if (err)
			goto free_key;
	}
	param->enckeylen = cpu_to_be32((x->ealg->alg_key_len + 7) / 8);	
	memcpy(p, x->ealg->alg_key, (x->ealg->alg_key_len + 7) / 8);

	err = crypto_aead_setkey(aead, key, keylen); //setkey

free_key:
	kfree(key);

error:
	return err; 
}

/*ALIGN    :#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
 *          #define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
 *          #you have a number: 0x1006 
 *          For some reasons you want to align it to a 4 bytes boundary.
 *          With a 4-byte boundary, you know aligned values are 0x1000, 0x1004, 
 *          0x1008, etc. You then also know the aligned value of 0x1006 is 0x1008.
 *          How would you get 0x1008? The alignment mask for alignment value 4 is 
 *          (4 - 1) = 0x03
 *          Now 0x1006 + 0x03 = 0x1009 and 0x1009 & ~0x03 = 0x1008
 *          If you want to pass the value 4 (the alignment) instead of directly 
 *          0x03 (the alignment mask), you have the ALIGN macro
*/
/*http://www.chronox.de/crypto-API/crypto/api-aead.html*/
static int esp_init_state(struct xfrm_state *x)
{
	struct crypto_aead *aead;
	u32 align;
	int err;
	x->data = NULL;

	if (x->aead)
		err = esp_init_aead(x);  //Authenticated Encryption With Associated Data (AEAD): The mostly type of encryption is GCM and CCM. 
	else
		err = esp_init_authenc(x);

	if (err)
		goto error;

	aead = x->data;
	x->props.header_len = sizeof(struct ip_esp_hdr) +         /* esp header size + ivsize initialization vector is the size of a block */
			      crypto_aead_ivsize(aead);
	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct iphdr);
	else if (x->props.mode == XFRM_MODE_BEET && x->sel.family != AF_INET6)
		x->props.header_len += IPV4_BEET_PHMAXLEN;
	
	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;

		switch (encap->encap_type) {
		default:
			goto error;
		case UDP_ENCAP_ESPINUDP:
			x->props.header_len += sizeof(struct udphdr);
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			x->props.header_len += sizeof(struct udphdr) + 2 * sizeof(u32);
			break;
		}
	}
//TODO
	align = ALIGN(crypto_aead_blocksize(aead), 4);
	x->props.trailer_len = align + 1 + crypto_aead_authsize(aead);

error:
	return err;
}
static int esp4_rcv_cb(struct sk_buff *skb, int err)
{
	return 0;
}

static const struct xfrm_type esp_type =
{
	.description	= "ESP4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_ESP,
	.flags		= XFRM_TYPE_REPLAY_PROT,
	.init_state	= esp_init_state,
	.destructor	= esp_destroy,
	.get_mtu	= esp4_get_mtu,
	.input		= esp_input,
	.output		= esp_output
};
/* XFRM protocol handlers.  */
static struct xfrm4_protocol esp4_protocol = {
	.handler	=	xfrm4_rcv,         // receiver
	.input_handler	=	xfrm_input,        // Sender
	.cb_handler	=	esp4_rcv_cb,       // Control buffer handler 
	.err_handler	=	esp4_err,
	.priority	=	0,
};


/*1. Registering XFRM type by calling the xfrm_register_type() method will set 
 *   the specified xfrm_type as an element in this array
 *   AF_INET         2       Internet IP Protocol        
 *2. Registering the IPv4 ESP protocol is done like registering any other IPv4 
 *   protocol, by calling the inet_add_protocol() method.
 *   IPPROTO_ESP = 50,          Encapsulation Security Payload protocol  
*/

/*Initialization  of driver : Registering XFRM type and Registering the IPv4 ESP*/
static int __init esp4_init(void)
{
	if (xfrm_register_type(&esp_type, AF_INET) < 0) {
		pr_info("%s: can't add xfrm type\n", __func__);
		return -EAGAIN;
	}
	if (xfrm4_protocol_register(&esp4_protocol, IPPROTO_ESP) < 0) {
		pr_info("%s: can't add protocol\n", __func__);
		xfrm_unregister_type(&esp_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

static void __exit esp4_fini(void)
{
	if (xfrm4_protocol_deregister(&esp4_protocol, IPPROTO_ESP) < 0)
		pr_info("%s: can't remove protocol\n", __func__);
	if (xfrm_unregister_type(&esp_type, AF_INET) < 0)
		pr_info("%s: can't remove xfrm type\n", __func__);
}


module_init(esp4_init);
module_exit(esp4_fini);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chandan Jha <beingchandanjha@gmail.com>");
MODULE_DESCRIPTION("IPsec module : For ESP protocol");
MODULE_ALIAS_XFRM_TYPE(AF_INET, XFRM_PROTO_ESP);

