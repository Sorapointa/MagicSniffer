const fs = require("fs")
const kcp = require("node-kcp-token")
const pcapParser = require("pcap-parser")
const { pcap } = require("./config.json")

const plainText = fs.readFileSync("./plaintext.bin")

const readIPv4Header = (buffer, offset = 0) => {
    const ipVersionNumber = parseInt(buffer[offset].toString(16)[0], 16)
    offset += 0
    const ihl = parseInt(buffer[offset].toString(16)[1], 16)
    offset += 1
    const serviceType = buffer[offset]
    offset += 1
    const totalLength = buffer.readUInt16LE(offset)
    offset += 16 / 8
    const identification = buffer.readUInt16LE(offset)
    offset += 16 / 8
    const flags = parseInt(buffer[offset].toString(16)[0], 16)
    offset += 0
    const fragmentOffset = ((buffer[offset] & 0x0F) << 8) | (buffer[offset + 1] & 0xFF)
    offset += 2
    const timeToLive = buffer[offset]
    offset += 1
    const protocol = buffer[offset]
    offset += 1
    const headerChecksum = buffer.readUInt16LE(offset)
    offset += 16 / 8
    const srcAddr = buffer.slice(offset, offset + (32 / 8)).toString("hex").match(/../g).map(byte => parseInt(byte, 16)).join(".")
    offset += 32 / 8
    const dstAddr = buffer.slice(offset, offset + (32 / 8)).toString("hex").match(/../g).map(byte => parseInt(byte, 16)).join(".")
    return {
        ipVersionNumber,
        ihl,
        serviceType,
        totalLength,
        identification,
        flags,
        fragmentOffset,
        timeToLive,
        protocol,
        headerChecksum,
        srcAddr,
        dstAddr
    }
}

const readUDPHeader = (buffer, offset = 20) => {
    const portSrc = buffer.readUint16BE(offset)
    offset += 16 / 8
    const portDst = buffer.readUint16BE(offset)
    offset += 16 / 8
    const length = buffer.readUint16BE(offset)
    offset += 16 / 8
    const checksum = buffer.readUint16BE(offset)
    offset += 16 / 8
    return {
        portSrc,
        portDst,
        length,
        checksum
    }
}

const stream = fs.createReadStream(pcap)
const parser = pcapParser.parse(stream)

const DIR_SERVER = 0
const DIR_CLIENT = 1

var serverBound = {}
var clientBound = {}

let allPackets = []

parser.on("packet", packet => {
    if (packet.data.readInt16LE(12) === 8) {
        packet.data = packet.data.slice(14)
    }

    let udp = readUDPHeader(packet.data)
    let ip = readIPv4Header(packet.data)

    let packetConfig = {
        crypt: packet.data.slice(28),
        ip: {
            from: ip.srcAddr,
            to: ip.dstAddr,
            fromPort: udp.portSrc,
            toPort: udp.portDst,
        },
        time: packet.header.timestampSeconds * 1000 + packet.header.timestampMicroseconds / 1000
    }

    let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;

    if (packetConfig.crypt.byteLength <= 20) {
        return
    }

    let KCPContentMap
    if (packetSource == DIR_SERVER) {
        KCPContentMap = serverBound
    } else {
        KCPContentMap = clientBound
    }

    let peerID = packetConfig.ip.from + "_" + packetConfig.ip.fromPort + "_" + packetConfig.crypt.readInt32LE(0).toString(16)

    if (!KCPContentMap[peerID]) {
        KCPContentMap[peerID] = new kcp.KCP(packetConfig.crypt.readInt32LE(0), packetConfig.crypt.readInt32LE(4), {
            address: packetConfig.ip.from,
            address_dst: packetConfig.ip.to,
            port: packetConfig.ip.fromPort,
            port_dst: packetConfig.ip.toPort
        })
    }

    KCPContentMap[peerID].input(packetConfig.crypt)
    var hrTime = process.hrtime()
    KCPContentMap[peerID].update(hrTime[0] * 1000000 + hrTime[1] / 1000)
    KCPContentMap[peerID].wndsize(1024, 1024)

    let recv
    let bPackets = []
    do {
        recv = KCPContentMap[peerID].recv()
        if (!recv) break
        bPackets.push(recv)
    } while (recv)
    hrTime = process.hrtime()
    KCPContentMap[peerID].update(hrTime[0] * 1000000 + hrTime[1] / 1000)

    packetConfig.bPackets = bPackets

    allPackets.push(packetConfig)
})

const xor = (data, key) => {
    for (let i = 0; i < data.length; i++) {
        data.writeUInt8(data.readUInt8(i) ^ key.readUInt8(i % key.length), i)
    }
}

const print = text => console.log(text)

const zero = (text, length) => {
    while (text.length < length) {
        text = "0" + text
    }
    return text
}

const sortDict = (dict) => { 
    let items = Object.keys(dict).map(key => {
        return [key, dict[key]]
    })
  
    return items.sort((first, second) => {
        return second[1] - first[1]
    })
}

parser.on("end", async () => {
    const dispatchHead = allPackets[0].bPackets[0].toString("hex").slice(0, 4)

    // MAGIC VARIATED IN DIFF VERSION
    let isLoginFound = false
    let plainLoginHead = 0x45670070
    let plainWindSeedHead = 0x456704AF
    let plainSceneTimeHead = 0x456700F5
    let plainSceneTimeHead2 = 0

    let headXORKey
    let windSeedHead
    let sceneTimeHead
    let headLengthXORKey

    allPackets.forEach(packet => {
        if (packet.bPackets.length > 0) {
            const hexString = packet.bPackets[0].toString("hex")
            const head = hexString.slice(0, 4)

            if (head != dispatchHead && !isLoginFound) {
                print("Found LoginReq!")
                const orgBytes = packet.bPackets[0].slice(0, 4).readInt32BE()
                headXORKey = orgBytes ^ plainLoginHead
                print("Head XOR Key Found: " + headXORKey.toString(16))
                sceneTimeHead = headXORKey ^ plainSceneTimeHead
                windSeedHead = headXORKey ^ plainWindSeedHead
                isLoginFound = true
            }

            if (isLoginFound) {
                if (!headLengthXORKey && hexString.startsWith(sceneTimeHead.toString(16))) {
                    const withHeadBytes = packet.bPackets[0].slice(4, 8).readInt16BE()
                    headLengthXORKey = withHeadBytes ^ plainSceneTimeHead2 // equals to withHeadBytes X ^ 0 = X
                    print("Found HeadLengthXorKey: " + headLengthXORKey.toString(16))
                } 
            }
        }
    })

    allPackets.forEach(packet => {
        if (packet.bPackets.length > 0) {
            const hexString = packet.bPackets[0].toString("hex")
            if (headLengthXORKey && hexString.startsWith(windSeedHead.toString(16)) && hexString.length > 2000) {
                let offset = packet.bPackets[0].slice(4, 8).readInt16BE() ^ headLengthXORKey
                offset += (4 + 4 + 4 + 8) / 2
                let sliceBytes = packet.bPackets[0].slice(offset)
                xor(sliceBytes, plainText)
                let sliceString = sliceBytes.toString("hex")
                const combinedKeyFeature = zero(headXORKey.toString(16), 8) + zero(headLengthXORKey.toString(16), 4)
                print("Combined Key Feature: " + combinedKeyFeature)
                let lastIndex = -1
                let index = 0
                let dict = {}
                while(index != -1) {
                    index = sliceString.indexOf(combinedKeyFeature, lastIndex + 1)
                    if (lastIndex > 0 && index - lastIndex == 4096 * 2) {
                        print("lastIndex: " + lastIndex + " index: " + index + " diff: " + (index - lastIndex))
                        const potentialKey = sliceString.slice(lastIndex, index)
                        dict[potentialKey] = (dict[potentialKey] || 0) + 1
                    }
                    lastIndex = index
                }
                const sortedDict = sortDict(dict)
                for (let key in sortedDict) {
                    print("Key: " + sortedDict[key][0].slice(0, 32) + " Count: " + sortedDict[key][1])
                }
                const file = fs.createWriteStream("key.txt")
                const finalKey = sortedDict[sortedDict.length - 1][0]
                const finalKeyBase64 = Buffer.from(finalKey, "hex").toString("base64")
                file.write(finalKeyBase64)
                file.end()
                return
            }
        }
    })
})
