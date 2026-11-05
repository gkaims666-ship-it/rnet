import Foundation
import Combine

// ServerConfig — persists user-configured relay endpoint (UserDefaults).
// Set via ServerSetupView on first launch; engine will not start without it.
struct ServerConfig {
    static let hostKey = "rnet_relay_host"
    static let portKey = "rnet_relay_port"

    static var host: String { UserDefaults.standard.string(forKey: hostKey) ?? "" }
    static var port: Int    { UserDefaults.standard.integer(forKey: portKey) == 0
                                ? 7777 : UserDefaults.standard.integer(forKey: portKey) }
    static var isConfigured: Bool { !host.isEmpty }

    static func save(host: String, port: Int) {
        UserDefaults.standard.set(host, forKey: hostKey)
        UserDefaults.standard.set(port, forKey: portKey)
    }
}

/// iOS ViewModel — mirrors Android MainViewModel.kt.
/// Owned by RnetApp and injected into the SwiftUI view hierarchy via @EnvironmentObject.
@MainActor
final class RnetViewModel: ObservableObject {

    // MARK: - Published state

    @Published var engineActive = false
    @Published var gatewayActive = false
    @Published var snrDb: Float = 0
    @Published var packetDeliveryRate: Float = 1.0
    @Published var technology = ""
    @Published var bandMhz = 0
    @Published var isLowBand = false
    @Published var totalBytesIn: Int64 = 0
    @Published var totalBytesOut: Int64 = 0
    @Published var activeEndpoint = ""
    @Published var errorMessage: String? = nil

    // Mesh
    @Published var meshPeers: [MeshPeerItem] = []
    @Published var isGateway = false

    struct MeshPeerItem: Identifiable {
        let id: String
        let displayName: String
        let hasUplink: Bool
        let rssi: Int
        let transport: String
    }

    // MARK: - Dependencies

    let engine = MultipathEngine()
    let mesh = MultipeerMesh()

    // MARK: - Engine toggle

    func toggleEngine(_ on: Bool) {
        Task {
            if on {
                do {
                    guard ServerConfig.isConfigured else {
                        errorMessage = "No relay server configured. Open Settings to add your relay."
                        return
                    }
                    // Placeholder: derive a real session key via HybridKeyExchange in production
                    let dummyKey = Data(repeating: 0xAB, count: 32)
                    try await engine.start(
                        host: ServerConfig.host,
                        port: ServerConfig.port,
                        sessionKey: dummyKey
                    )
                    engineActive = true
                } catch {
                    errorMessage = error.localizedDescription
                }
            } else {
                engine.stop()
                engineActive = false
            }
        }
    }

    // MARK: - Mesh

    func startMesh() {
        mesh.start()
    }

    func stopMesh() {
        mesh.stop()
    }

    func enableGatewayMode(consentGranted: Bool) {
        guard consentGranted else { return }
        isGateway = true
        // Wire inbound engine → mesh broadcast; mesh inbound → engine send
        mesh.inboundHandler = { [weak self] data, _ in
            Task { await try? self?.engine.send(data) }
        }
        engine.inboundHandler = { [weak self] data in
            try? self?.mesh.broadcast(data)
        }
    }

    // MARK: - Telemetry sink (called by background timer)

    func syncTelemetry() {
        packetDeliveryRate = engine.packetDeliveryRate
        totalBytesIn = engine.totalBytesIn
        totalBytesOut = engine.totalBytesOut
        meshPeers = mesh.connectedPeers.map {
            MeshPeerItem(id: $0.displayName, displayName: $0.displayName,
                         hasUplink: false, rssi: 0, transport: "MultipeerConnectivity")
        }
    }
}
