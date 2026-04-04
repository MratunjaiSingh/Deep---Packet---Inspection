const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Cap = require('cap').Cap;
const decoders = require('cap').decoders;
const geoip = require('geoip-lite');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

const c = new Cap();
// 🔥 Auto-detect interface or fallback to eth0
const device = Cap.findDevice() || 'eth0'; 
const filter = 'ip'; 
const buffer = Buffer.alloc(65535);

try {
    c.open(device, filter, 50 * 1024 * 1024, buffer);
    console.log(`✅ Monitoring Active on: ${device}`);
} catch (e) {
    console.log("⚠️ Fallback to eth0...");
    c.open('eth0', filter, 50 * 1024 * 1024, buffer);
}

let totalBytes = 0;
let droppedPackets = 0; 
let blockedStats = {}; 
const blacklistedIPs = ['8.8.8.8', '1.1.1.1', '1.2.3.4']; 

c.on('packet', (nbytes) => {
    totalBytes += nbytes; 
    let ret = decoders.Ethernet(buffer);
    if (ret.info.type === decoders.PROTOCOL.ETHERNET.IPV4) {
        ret = decoders.IPV4(buffer, ret.offset);
        let srcIp = ret.info.srcaddr;
        let dstIp = ret.info.dstaddr;
        let protoNum = ret.info.protocol;
        let proto = (protoNum === 6) ? 'TCP' : (protoNum === 17 ? 'UDP' : 'ICMP');
        
        let srcPort = 0, dstPort = 0;
        if (protoNum === 6) { 
            let t = decoders.TCP(buffer, ret.offset); 
            srcPort = t.info.srcport; dstPort = t.info.dstport; 
        }

        // --- 🛡️ FIREWALL LOGIC ---
        let isBlocked = blacklistedIPs.includes(dstIp) || blacklistedIPs.includes(srcIp);
        if (isBlocked) {
            droppedPackets++;
            let attacker = blacklistedIPs.includes(srcIp) ? srcIp : dstIp;
            blockedStats[attacker] = (blockedStats[attacker] || 0) + 1;
        }

        // --- 🌍 GEO-IP & LB ---
        let geo = geoip.lookup(dstIp);
        let country = (geo && geo.country) ? "🚩 " + geo.country : "🌐 Public";
        let lbStatus = "❌ No LB";
        
        // --- 🕵️ HYBRID DPI ENGINE ---
        let appName = (dstPort === 443 || srcPort === 443) ? "HTTPS SSL" : "General Web";
        
        // IP Based (Speed optimized)
        const ipMap = { '103.102.166': 'Wikipedia', '142.250': 'Google', '172.217': 'YouTube', '157.240': 'WhatsApp', '31.13': 'Facebook' };
        for (let r in ipMap) { if (dstIp.startsWith(r)) appName = ipMap[r]; }

        if (proto === 'TCP') {
            let tcpRet = decoders.TCP(buffer, ret.offset);
            let payload = buffer.slice(tcpRet.offset, nbytes);
            if (payload[0] === 0x16) { // TLS Handshake
                const rawData = payload.toString('binary').toLowerCase();
                if (rawData.includes('wikipedia')) appName = "Wikipedia";
                else if (rawData.includes('youtube')) appName = "YouTube";
                else if (rawData.includes('google')) appName = "Google";
                else if (rawData.includes('geeksforgeeks')) appName = "GeeksforGeeks";
                else if (rawData.includes('leetcode')) appName = "LeetCode";
            }
        }

        io.emit('packet', { 
            src: srcIp, dst: dstIp, proto: proto, 
            country: country, app: appName, lb: lbStatus,
            isBlocked: isBlocked, dropCount: droppedPackets,
            topBlocked: blockedStats
        });
    }
});


// --- Updated Speed Calculation Logic ---
let intervalBytes = 0; // Naya variable bandwidth ke liye

c.on('packet', (nbytes) => {
    totalBytes += nbytes; 
    intervalBytes += nbytes; // Isme har packet ke bytes add hote rahenge
    
    // ... baaki packet processing same rahegi ...
});

setInterval(() => {
    // Bits per second to Kbps: (bytes * 8) / 1024
    let speedKbps = ((intervalBytes * 8) / 1024).toFixed(2);
    io.emit('speed', speedKbps);
    
    console.log(`📡 Current Speed: ${speedKbps} Kbps`); // Terminal mein check karne ke liye
    intervalBytes = 0; // Har second reset hoga taaki nayi speed mile
}, 1000);

server.listen(3000, () => console.log('🚀 SYSTEM LIVE: http://localhost:3000'));