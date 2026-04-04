const Cap = require('cap').Cap;
const decoders = require('cap').decoders;
const PROTOCOL = decoders.PROTOCOL;

const c = new Cap();
const device = 'eth0'; 
const filter = 'tcp or udp';
const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

try {
    const linkType = c.open(device, filter, bufSize, buffer);
    console.log(`--- 🕵️ DAY 1: Sniffer Started on ${device} ---`);

    c.on('packet', (nbytes, trunc) => {
        if (linkType === 'ETHERNET') {
            let ret = decoders.Ethernet(buffer);
            if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
                ret = decoders.IPV4(buffer, ret.offset);
                const srcIp = ret.info.srcaddr;
                const destIp = ret.info.dstaddr;

                if (ret.info.protocol === PROTOCOL.IP.TCP) {
                    ret = decoders.TCP(buffer, ret.offset);
                    console.log(`[TCP] ${srcIp}:${ret.info.srcport} -> ${destIp}:${ret.info.dstport}`);
                } 
                else if (ret.info.protocol === PROTOCOL.IP.UDP) {
                    ret = decoders.UDP(buffer, ret.offset);
                    console.log(`[UDP] ${srcIp}:${ret.info.srcport} -> ${destIp}:${ret.info.dstport}`);
                }
            }
        }
    });
} catch (err) {
    console.log("Error: Interface nahi mila. 'ip addr' chala kar check karein.");
}

