import Foundation
import MultipeerConnectivity

/// iOS mesh layer using MultipeerConnectivity.
///
/// Design mirrors Android WifiDirectMesh.kt + BleMeshScanner.kt:
///   - Service type: "rnet-mesh" (must be ≤ 15 chars, lowercase alphanumeric + hyphens)
///   - Peer discovery via MCNearbyServiceBrowser + MCNearbyServiceAdvertiser
///   - Data plane: MCSession sendData with .reliable delivery
///   - CONSENT GATE: every incoming connection invitation is held until the user
///     explicitly accepts via MeshConsentView; invitations are NEVER auto-accepted.
///
/// MultipeerConnectivity uses Wi-Fi Infrastructure, Wi-Fi Direct (AWDL), and
/// Bluetooth automatically depending on hardware availability.

@MainActor
final class MultipeerMesh: NSObject, ObservableObject {

    static let serviceType = "rnet-mesh"

    // MARK: - Published state

    @Published private(set) var discoveredPeers: [MCPeerID] = []
    @Published private(set) var connectedPeers: [MCPeerID] = []
    @Published private(set) var pendingInvitation: PendingInvitation?

    struct PendingInvitation {
        let peer: MCPeerID
        let invitationHandler: (Bool, MCSession?) -> Void
    }

    // MARK: - Private

    private let localPeer: MCPeerID
    private lazy var session: MCSession = {
        let s = MCSession(peer: localPeer, securityIdentity: nil, encryptionPreference: .required)
        s.delegate = self
        return s
    }()
    private lazy var advertiser: MCNearbyServiceAdvertiser = {
        let a = MCNearbyServiceAdvertiser(
            peer: localPeer,
            discoveryInfo: ["rnet": "1"],
            serviceType: Self.serviceType
        )
        a.delegate = self
        return a
    }()
    private lazy var browser: MCNearbyServiceBrowser = {
        let b = MCNearbyServiceBrowser(peer: localPeer, serviceType: Self.serviceType)
        b.delegate = self
        return b
    }()

    var inboundHandler: ((Data, MCPeerID) -> Void)?

    // MARK: - Init

    init(displayName: String = UIDevice.current.name) {
        localPeer = MCPeerID(displayName: displayName)
        super.init()
    }

    // MARK: - Lifecycle

    func start() {
        advertiser.startAdvertisingPeer()
        browser.startBrowsingForPeers()
    }

    func stop() {
        advertiser.stopAdvertisingPeer()
        browser.stopBrowsingForPeers()
        session.disconnect()
    }

    // MARK: - Consent handling

    /// Called by MeshConsentView when the user accepts an incoming invitation.
    func acceptInvitation() {
        guard let inv = pendingInvitation else { return }
        inv.invitationHandler(true, session)
        pendingInvitation = nil
    }

    /// Called by MeshConsentView when the user declines.
    func declineInvitation() {
        guard let inv = pendingInvitation else { return }
        inv.invitationHandler(false, nil)
        pendingInvitation = nil
    }

    /// Initiates an outgoing connection request to [peer].
    /// Must only be called after the user has explicitly consented via MeshConsentView.
    func connect(to peer: MCPeerID, consentGranted: Bool) {
        precondition(consentGranted, "Must obtain user consent before connecting to mesh peer")
        browser.invitePeer(peer, to: session, withContext: nil, timeout: 30)
    }

    // MARK: - Send

    func broadcast(_ data: Data) throws {
        guard !connectedPeers.isEmpty else { return }
        try session.send(data, toPeers: connectedPeers, with: .reliable)
    }

    func send(_ data: Data, to peer: MCPeerID) throws {
        try session.send(data, toPeers: [peer], with: .reliable)
    }
}

// MARK: - MCSessionDelegate

extension MultipeerMesh: MCSessionDelegate {
    nonisolated func session(_ session: MCSession, peer: MCPeerID, didChange state: MCSessionState) {
        Task { @MainActor in
            switch state {
            case .connected:
                if !connectedPeers.contains(peer) { connectedPeers.append(peer) }
            case .notConnected:
                connectedPeers.removeAll { $0 == peer }
            default: break
            }
        }
    }

    nonisolated func session(_ session: MCSession, didReceive data: Data, fromPeer peer: MCPeerID) {
        Task { @MainActor in inboundHandler?(data, peer) }
    }

    nonisolated func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer: MCPeerID) {}
    nonisolated func session(_ session: MCSession, didStartReceivingResourceWithName: String, fromPeer: MCPeerID, with: Progress) {}
    nonisolated func session(_ session: MCSession, didFinishReceivingResourceWithName: String, fromPeer: MCPeerID, at: URL?, withError: Error?) {}
}

// MARK: - MCNearbyServiceAdvertiserDelegate

extension MultipeerMesh: MCNearbyServiceAdvertiserDelegate {
    nonisolated func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peer: MCPeerID, withContext: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        Task { @MainActor in
            // CONSENT GATE: surface to UI, do NOT auto-accept
            pendingInvitation = PendingInvitation(peer: peer, invitationHandler: invitationHandler)
        }
    }
}

// MARK: - MCNearbyServiceBrowserDelegate

extension MultipeerMesh: MCNearbyServiceBrowserDelegate {
    nonisolated func browser(_ browser: MCNearbyServiceBrowser, foundPeer peer: MCPeerID, withDiscoveryInfo: [String: String]?) {
        Task { @MainActor in
            if !discoveredPeers.contains(peer) { discoveredPeers.append(peer) }
        }
    }

    nonisolated func browser(_ browser: MCNearbyServiceBrowser, lostPeer peer: MCPeerID) {
        Task { @MainActor in
            discoveredPeers.removeAll { $0 == peer }
            connectedPeers.removeAll { $0 == peer }
        }
    }
}
