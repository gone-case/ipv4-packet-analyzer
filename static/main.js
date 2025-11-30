let currentFile = null;

async function uploadPCAP() {
    let fileInput = document.getElementById("pcapFile");
    if (!fileInput.files.length) {
        alert("Please choose a pcap file");
        return;
    }

    let fd = new FormData();
    fd.append("pcap", fileInput.files[0]);

    let res = await fetch("/upload", { method: "POST", body: fd });
    let data = await res.json();

    if (data.error) {
        alert("Upload failed");
        return;
    }

    currentFile = data.filename;
    loadPacketList();
}

async function loadPacketList() {
    let res = await fetch(`/packets/${currentFile}`);
    let packets = await res.json();

    let ul = document.getElementById("packets");
    ul.innerHTML = "";

    packets.forEach(p => {
        let li = document.createElement("li");
        li.innerText = `#${p.pkt_id} — ${p.src} → ${p.dst} (proto ${p.protocol}, ttl ${p.ttl})`;
        li.onclick = () => loadPacketDetails(p.pkt_id);
        ul.appendChild(li);
    });
}

async function loadPacketDetails(id) {
    let res = await fetch(`/packet/${currentFile}/${id}`);
    let p = await res.json();

    // Fill header boxes
    document.getElementById("versionBox").innerText = "Version: " + p.version;
    document.getElementById("ihlBox").innerText = "IHL: " + p.ihl;
    document.getElementById("tosBox").innerText = "TOS: " + p.tos;
    document.getElementById("totalLenBox").innerText = "Total Length: " + p.total_length;

    document.getElementById("identBox").innerText = "Identification: " + p.id;
    document.getElementById("flagsBox").innerText = "Flags: " + p.flags;
    document.getElementById("fragOffsetBox").innerText = "Fragment Offset: " + p.frag_offset;

    document.getElementById("ttlBox").innerText = "TTL: " + p.ttl;

    let protocolName =
        (p.protocol === 1 ? "ICMP" :
         p.protocol === 6 ? "TCP" :
         p.protocol === 17 ? "UDP" : "Unknown");

    document.getElementById("protocolBox").innerText =
        "Protocol: " + p.protocol + " (" + protocolName + ")";

    document.getElementById("checksumBox").innerText = "Checksum: " + p.checksum;
    document.getElementById("srcIPBox").innerText = "Source: " + p.src_ip;
    document.getElementById("dstIPBox").innerText = "Destination: " + p.dst_ip;
    document.getElementById("optionsBox").innerText = "Options: " + (p.options || "None");

    // Extra details section
    document.getElementById("extraDetails").innerHTML = `
        <b>Header Length:</b> ${p.ihl * 4} bytes<br>
        <b>Payload Length:</b> ${p.payload_len} bytes<br>
        <b>Total Packet Size:</b> ${p.total_length} bytes<br>
        <b>Protocol Meaning:</b> ${protocolName}<br>
        <b>Flags Meaning:</b> ${p.flags === 1 ? "More Fragments (MF=1)" : "Last Fragment"}<br>
        <b>Fragment Offset (bytes):</b> ${p.frag_offset * 8}<br>
        <b>Timestamp:</b> ${p.ts}
    `;

    // Raw hex
    document.getElementById("rawHex").innerText = p.raw_bytes;
}
