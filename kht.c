#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

/* This function to be called by hook. */
static unsigned int
hook_func(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
    struct udphdr *udp_header;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    if (ip_header->protocol == 17) {
        udp_header = (struct udphdr *)skb_transport_header(skb);
        printk(KERN_INFO "Got an udp packet.\n");

        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook       = hook_func,
    .hooknum    = 1, /* NF_IP_LOCAL_IN */
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

int init_module(void)
{
	printk(KERN_INFO "kht: init_module()\n");

  nf_register_hook(&nfho);                     //register hook

	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "kht: cleanup_module()\n");

  nf_unregister_hook(&nfho);                     //cleanup – unregister hook
}
