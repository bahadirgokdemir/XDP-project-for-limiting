#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define KEYWORD_LEN 5
#define MAX_MAP_ENTRIES 1024

struct ip4_trie_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, struct ip4_trie_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_dvbs_map SEC(".maps");

SEC("xdp_deneme")
int xdp_program(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end)
    {
        bpf_printk("Invalid ETHERNET header\n");
        return XDP_DROP;
    }

    struct iphdr *iph = (data + sizeof(struct ethhdr));
    if (iph + 1 > (struct iphdr *)data_end)
    {
        bpf_printk("Invalid IP header\n");
        return XDP_DROP;
    }

    // IP adresinin 192.168 ile başlamasını kontrol et
    __u32 ip_src = bpf_ntohl(iph->saddr);
    //if ((ip_src & 0xFFFF0000) != 0xC0A80000) {
      //  bpf_printk("Invalid source IP address\n");
        //return XDP_DROP;
    //}

    bpf_printk("IP Source Address: %u\n", ip_src);


    // IPPROTO_TCP tanımlaması kontrolü
    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if (tcph + 1 > (struct tcphdr *)data_end)
        {
            bpf_printk("Invalid TCP header\n");
            return XDP_DROP;
        }

        if (tcph->dest == bpf_htons(80))
        {
            char *payload = (char *)((unsigned char *)tcph + (tcph->doff << 2));

            const char *keyword = "keyword";

            int payload_len = (void *)data_end - (void *)payload;

            // Keyword uzunluğunun 5'ten uzun olmasını kontrol et
            if (payload_len >= KEYWORD_LEN)
            {
                int i = 0;
                while (i <= 150)
                {
                    if (i > payload_len - KEYWORD_LEN)
                        break;

                    int match = 1;
                    int j = 0;

                    for (j = 0; j < KEYWORD_LEN; j++)
                    {
                        char *hop = payload + i + j;

                        // Out of bounds kontrolü
                        if ((void *)hop >= data_end)
                        {
                            bpf_printk("Out of bounds\n");
                            break;
                        }

                        if (*hop != keyword[j])
                        {
                            match = 0;
                            break;
                        }
                    }

                    if (match)
                    {
                        // IP adresini BPF map'inden al ve kontrol et
                        struct ip4_trie_key target_ip_key = {
                            .prefixlen = 24,  // 192.168.0.0/24
                            .addr = {0xC0, 0xA8, 0x00, 0x00},  // 192.168.0.0
                        };

                        __u32 *value = bpf_map_lookup_elem(&xdp_dvbs_map, &target_ip_key);
                        if (value && (ip_src & *value) == (target_ip_key.addr[0] << 24 | target_ip_key.addr[1] << 16 | target_ip_key.addr[2] << 8 | target_ip_key.addr[3]))
                        {
                            bpf_printk("Keyword matched: keyword. IP matched: 192.168.0.0/24\n");
                            return XDP_DROP;
                        }
                    }

                    i++;
                }
            }
        }
    }

    bpf_printk("PASS\n");
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

