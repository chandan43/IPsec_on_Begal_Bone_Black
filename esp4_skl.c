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

static int esp_init_state(struct xfrm_state *x)
{
	return 0;
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

