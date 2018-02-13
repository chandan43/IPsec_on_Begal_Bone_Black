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

static int esp_init_state(struct xfrm_state *x)
{
	struct crypto_aead *aead;
	u32 align;
	int err;
	x->data = NULL;

	if (x->aead)
		err = esp_init_aead(x);
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

