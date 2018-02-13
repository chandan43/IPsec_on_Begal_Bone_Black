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
	return 0;
}
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
	return 0;
}

static u32 esp4_get_mtu(struct xfrm_state *x, int mtu)
{
	return 0;
}

static int esp4_err(struct sk_buff *skb, u32 info)
{
	return 0;
}

static void esp_destroy(struct xfrm_state *x)
{

}
//TODO
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
				 (x->aead->alg_key_len + 7) / 8);
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

