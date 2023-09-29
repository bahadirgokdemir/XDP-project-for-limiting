#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

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
int xdp_drop_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

       // Paket boyutunu kontrol et
    if (eth + 1 > data_end) {
        bpf_printk("Ether frame size check failed\n");
        return XDP_DROP;
    }
    
    bpf_printk("Ethernet Header: eth->h_proto = 0x%04x\n", eth->h_proto);
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    if(ip + 1 > data_end) {
        bpf_printk("IP Packet size check failed\n");
        return XDP_DROP;
    }
    
    // IP başlığı uzunluğu kontrolü
    if (ip->ihl != 5) {
        bpf_printk("IP version or header length check failed (ihl: %x)\n", ip->ihl);
        return XDP_DROP;
    }

    if (ip->version != 4) {
        bpf_printk("IP version or header length check failed (version: %d)\n", ip->version);
        return XDP_DROP;
    }

    if (eth + 1 > (struct ethhdr *)data_end)
    {
        bpf_printk("Invalid ETHERNET header\n");
        return XDP_DROP;
    }

        // Sadece 192.168.*.* IP adreslerini geçebilir
    struct ip4_trie_key target_ip_key = {
        .prefixlen = 24,  // 192.168.0.0/24
        .addr = {0xC0, 0xA8, 0x00, 0x00},  // 192.168.0.0
    };

     __u32 *value = bpf_map_lookup_elem(&xdp_dvbs_map, &target_ip_key);
    if (value && (void *)ctx->data_end - data >= 14) {  // Minimum Ethernet frame size
        // IP adresini kontrol et
        if ((ip->daddr & *value) == (target_ip_key.addr[0] << 24 | target_ip_key.addr[1] << 16 | target_ip_key.addr[2] << 8 | target_ip_key.addr[3])) {
            // Keyword kontrolü
            char *payload = data + sizeof(struct ethhdr) + ip->ihl * 4;
            int payload_length = (char *)ctx->data_end - (char *)payload;
            if (payload_length > 4) {
                bpf_printk("Packet passed all checks\n");
                return XDP_PASS;
            
            }
        }
    }

    bpf_printk("Packet dropped\n");
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
