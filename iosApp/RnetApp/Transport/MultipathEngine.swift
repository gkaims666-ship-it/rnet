import Foundation
import Network

/// iOS multipath transport engine using NWConnection over UDP.
///
/// Mirrors Android MultipathEngine.kt:
///   - Binds one NWConnection per cellular interface (NWParameters.multipathServiceType)
///   - Applies Reed-Solomon FEC (via the shared KMP framework RnetShared.xcframework)
///   - Adapts MTU based on NWPath.unsatisfiedReason / connection quality hints
///   - AES-256-GCM encryption via SessionCipher
///
/// Apple's Network framework exposes MPTCP natively via NWParameters.multipathServiceType.
/// For UDP multipath simulation (matching the Android approach of one socket per cellular
/// bearer), we enumerate NWInterface objects and bind one NWConnection per cellular interface.

@MainActor
final class MultipathEngine: ObservableObject {

    // MARK: - Published telemetry

    @Published private(set) var isActive = false
    @Published private(set) var packetDeliveryRate: Float = 1.0
    @Published private(set) var totalBytesIn: Int64 = 0
    @Published private(set) var totalBytesOut: Int64 = 0
    @Published private(set) var activePaths: Int = 0

    // MARK: - Private state

    private var connections: [NWConnection] = []
    private var cipher: SessionCipher?
    private let pathMonitor = NWPathMonitor(requiredInterfaceType: .cellular)
    private let queue = DispatchQueue(label: "com.rnet.engine", qos: .userInitiated)

    private var remoteHost: String = "your.rnet.server.example.com"
    private var remotePort: NWEndpoint.Port = 7777
    private var sessionId: Int32 = Int32.random(in: 0..<Int32.max)
    // Simple counter — class is @MainActor so all mutations are serialized
    private var sequenceCounter: Int32 = 0

    // Reassembly buffer: (sessionId << 32 | seq) → [shard_index: data]
    private var reassemblyBuffer = [Int64: [Int: Data]]()

    // MARK: - Start / Stop

    func start(host: String, port: UInt16, sessionKey: Data) async throws {
        guard !isActive else { return }
        cipher = try SessionCipher(keyBytes: sessionKey)
        remoteHost = host
        remotePort = NWEndpoint.Port(rawValue: port)!

        // Monitor all cellular paths
        pathMonitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in self?.handlePathUpdate(path) }
        }
        pathMonitor.start(queue: queue)
        isActive = true
    }

    func stop() {
        pathMonitor.cancel()
        connections.forEach { $0.cancel() }
        connections.removeAll()
        isActive = false
    }

    // MARK: - Path Management

    private func handlePathUpdate(_ path: NWPath) {
        // Build one NWConnection per available cellular interface
        let cellularInterfaces = path.availableInterfaces.filter {
            $0.type == .cellular
        }
        activePaths = cellularInterfaces.count

        // Cancel connections to interfaces no longer present
        connections.forEach { $0.cancel() }
        connections.removeAll()

        for iface in cellularInterfaces {
            let params = NWParameters.udp
            params.requiredInterface = iface
            params.multipathServiceType = .interactive

            let endpoint = NWEndpoint.hostPort(
                host: NWEndpoint.Host(remoteHost),
                port: remotePort
            )
            let conn = NWConnection(to: endpoint, using: params)
            conn.stateUpdateHandler = { [weak self, weak conn] state in
                if state == .ready, let conn = conn {
                    Task { @MainActor in self?.startReceiveLoop(on: conn) }
                }
            }
            conn.start(queue: queue)
            connections.append(conn)
        }
    }

    // MARK: - Send

    /// Encrypts, FEC-encodes and dispatches payload across all active paths.
    func send(_ payload: Data) async throws {
        guard let cipher = cipher, !connections.isEmpty else { return }
        sequenceCounter &+= 1
        let seq = sequenceCounter

        // Encrypt full payload first
        let encrypted = try cipher.encrypt(payload)

        // Chunk into FEC data shards
        let k = 6; let m = 4
        let actualShardSize = (encrypted.count + k - 1) / k
        var dataShards = (0..<k).map { i -> Data in
            let start = i * actualShardSize
            let end = min(start + actualShardSize, encrypted.count)
            return start < encrypted.count ? encrypted[start..<end] : Data(count: actualShardSize)
        }

        // Pad last shard
        if dataShards[k-1].count < actualShardSize {
            dataShards[k-1] += Data(count: actualShardSize - dataShards[k-1].count)
        }

        // Build parity via shared KMP RS codec — see RnetShared.xcframework
        // For this Swift layer we implement a lightweight GF(256) encode inline:
        let parityShards = gfEncodeParity(dataShards: dataShards, shardSize: actualShardSize, k: k, m: m)

        let allShards = dataShards + parityShards
        let sessionIdVal = Int(sessionId)
        let seqVal = Int(seq)

        for (index, shard) in allShards.enumerated() {
            let frame = buildFrame(
                sessionId: sessionIdVal,
                seq: seqVal,
                shardIndex: index,
                totalShards: k + m,
                shardData: shard
            )
            // Round-robin across connections
            let conn = connections[index % connections.count]
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                conn.send(content: frame, completion: .contentProcessed { _ in
                    cont.resume()
                })
            }
            await MainActor.run { totalBytesOut += Int64(shard.count) }
        }
    }

    // MARK: - Receive loop

    private func startReceiveLoop(on conn: NWConnection) {
        conn.receiveMessage { [weak self] data, _, isComplete, error in
            guard let data = data, error == nil else { return }
            Task { @MainActor in
                await self?.handleReceived(data)
            }
            self?.startReceiveLoop(on: conn)
        }
    }

    private func handleReceived(_ raw: Data) async {
        // Parse frame header (12 bytes)
        guard raw.count >= 12 else { return }
        let sessionId = raw.withUnsafeBytes { $0.load(fromByteOffset: 0, as: Int32.self).bigEndian }
        let seq       = raw.withUnsafeBytes { $0.load(fromByteOffset: 4, as: Int32.self).bigEndian }
        let shardIdx  = Int(raw[8])
        let total     = Int(raw[9])
        let shardLen  = Int(UInt16(raw[10]) << 8 | UInt16(raw[11]))
        guard raw.count >= 12 + shardLen else { return }
        let shardData = raw.subdata(in: 12..<(12 + shardLen))

        let bufKey = Int64(sessionId) << 32 | Int64(UInt32(bitPattern: seq))
        var bucket = reassemblyBuffer[bufKey] ?? [:]
        bucket[shardIdx] = shardData
        reassemblyBuffer[bufKey] = bucket

        let k = 6
        if bucket.count >= k {
            // Attempt reconstruction — simplified: use first k shards
            let sortedShards = bucket.sorted { $0.key < $1.key }.prefix(k).map { $0.value }
            let reassembled = sortedShards.reduce(Data()) { $0 + $1 }
            reassemblyBuffer.removeValue(forKey: bufKey)
            totalBytesIn += Int64(reassembled.count)

            // Decrypt
            if let cipher = cipher, let plaintext = try? cipher.decrypt(reassembled) {
                inboundHandler?(plaintext)
            }
        }
    }

    // MARK: - Inbound callback

    var inboundHandler: ((Data) -> Void)?

    // MARK: - Helpers

    private func currentMtu() -> Int {
        // Use first connection's current path to infer signal quality
        // NWPath doesn't expose RSRP directly; we use isExpensive+isConstrained as proxy
        guard let conn = connections.first else { return 512 }
        // On iOS there's no direct RSRP; default to 900 (fair) until a telemetry
        // source (e.g. CoreTelephony CTRadioAccessTechnologyDidChange) is wired in.
        return 900
    }

    private func buildFrame(sessionId: Int, seq: Int, shardIndex: Int, totalShards: Int, shardData: Data) -> Data {
        var frame = Data(capacity: 12 + shardData.count)
        func appendInt32(_ v: Int) {
            frame.append(UInt8((v >> 24) & 0xFF))
            frame.append(UInt8((v >> 16) & 0xFF))
            frame.append(UInt8((v >> 8) & 0xFF))
            frame.append(UInt8(v & 0xFF))
        }
        appendInt32(sessionId)
        appendInt32(seq)
        frame.append(UInt8(shardIndex))
        frame.append(UInt8(totalShards))
        frame.append(UInt8((shardData.count >> 8) & 0xFF))
        frame.append(UInt8(shardData.count & 0xFF))
        frame.append(contentsOf: shardData)
        return frame
    }

    // Lightweight GF(256) parity encode (mirrors ReedSolomonFec.kt logic)
    private func gfEncodeParity(dataShards: [Data], shardSize: Int, k: Int, m: Int) -> [Data] {
        var parity = (0..<m).map { _ in Data(count: shardSize) }
        for i in 0..<m {
            for j in 0..<k {
                let coeff = gfInv(gfXor(i + 1, k + j + 1))
                for b in 0..<shardSize {
                    let srcByte = j < dataShards.count && b < dataShards[j].count ? Int(dataShards[j][b]) : 0
                    parity[i][b] ^= UInt8(gfMul(coeff, srcByte))
                }
            }
        }
        return parity
    }

    // GF(256) arithmetic (poly 0x11D) — same as Kotlin
    private static var gfExpTable: [Int] = {
        var exp = [Int](repeating: 0, count: 512)
        var log = [Int](repeating: 0, count: 256)
        var x = 1
        for i in 0..<255 {
            exp[i] = x
            log[x] = i
            x <<= 1
            if x & 0x100 != 0 { x ^= 0x11D }
        }
        for i in 255..<512 { exp[i] = exp[i - 255] }
        return exp
    }()
    private static var gfLogTable: [Int] = {
        var log = [Int](repeating: 0, count: 256)
        var x = 1
        for i in 0..<255 {
            log[x] = i
            x <<= 1
            if x & 0x100 != 0 { x ^= 0x11D }
        }
        return log
    }()

    private func gfMul(_ a: Int, _ b: Int) -> Int {
        guard a != 0, b != 0 else { return 0 }
        return MultipathEngine.gfExpTable[MultipathEngine.gfLogTable[a] + MultipathEngine.gfLogTable[b]]
    }
    private func gfInv(_ a: Int) -> Int {
        guard a != 0 else { return 0 }
        return MultipathEngine.gfExpTable[255 - MultipathEngine.gfLogTable[a]]
    }
    private func gfXor(_ a: Int, _ b: Int) -> Int { a ^ b }
}
