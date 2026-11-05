import SwiftUI

/// Root SwiftUI view — mirrors Android MainActivity / MainScreen composable.
struct ContentView: View {
    @EnvironmentObject var vm: RnetViewModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    EngineCard()
                    TelemetryCard()
                    MeshCard()
                }
                .padding()
            }
            .navigationTitle("RNET")
            .navigationBarTitleDisplayMode(.large)
            .background(Color(.systemGroupedBackground).ignoresSafeArea())
        }
        .environmentObject(vm)
    }
}

// MARK: - Engine Card

struct EngineCard: View {
    @EnvironmentObject var vm: RnetViewModel

    var body: some View {
        RnetCard {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Multi-Path Transport")
                        .font(.headline)
                    Text(vm.engineActive ? "Active — multi-path running" : "Inactive")
                        .font(.subheadline)
                        .foregroundStyle(vm.engineActive ? .green : .secondary)
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { vm.engineActive },
                    set: { vm.toggleEngine($0) }
                ))
                .labelsHidden()
            }

            if let error = vm.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.top, 4)
            }
        }
    }
}

// MARK: - Telemetry Card

struct TelemetryCard: View {
    @EnvironmentObject var vm: RnetViewModel

    var body: some View {
        RnetCard {
            VStack(alignment: .leading, spacing: 12) {
                Text("Link Telemetry")
                    .font(.headline)

                MetricRow(label: "Packet Delivery Rate",
                          value: String(format: "%.1f%%", vm.packetDeliveryRate * 100))
                MetricRow(label: "Radio Technology",
                          value: vm.technology.isEmpty ? "—" : vm.technology)
                MetricRow(label: "Band",
                          value: vm.bandMhz > 0 ? "\(vm.bandMhz) MHz\(vm.isLowBand ? " (low-band)" : "")" : "—")
                MetricRow(label: "Data In",  value: formatBytes(vm.totalBytesIn))
                MetricRow(label: "Data Out", value: formatBytes(vm.totalBytesOut))
                if !vm.activeEndpoint.isEmpty {
                    MetricRow(label: "Active Endpoint", value: vm.activeEndpoint)
                }
            }
        }
    }

    private func formatBytes(_ b: Int64) -> String {
        let kb = Double(b) / 1024
        if kb < 1024 { return String(format: "%.1f KB", kb) }
        return String(format: "%.2f MB", kb / 1024)
    }
}

// MARK: - Mesh Card

struct MeshCard: View {
    @EnvironmentObject var vm: RnetViewModel
    @State private var showGatewayConsent = false

    var body: some View {
        RnetCard {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Ad-Hoc Mesh")
                        .font(.headline)
                    Spacer()
                    if vm.isGateway {
                        Label("Gateway", systemImage: "arrow.triangle.branch")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }

                if vm.meshPeers.isEmpty {
                    Text("Scanning for peers…")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(vm.meshPeers) { peer in
                        HStack {
                            Image(systemName: peer.hasUplink ? "wifi" : "wifi.slash")
                                .foregroundStyle(peer.hasUplink ? .green : .secondary)
                            VStack(alignment: .leading) {
                                Text(peer.displayName).font(.subheadline)
                                Text(peer.transport).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Divider()

                // Incoming invitation alert (consent gate)
                if let invitation = vm.mesh.pendingInvitation {
                    MeshInvitationBanner(peer: invitation.peer)
                }

                Button {
                    showGatewayConsent = true
                } label: {
                    Label("Enable Gateway Mode", systemImage: "antenna.radiowaves.left.and.right")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(vm.isGateway)
            }
        }
        .sheet(isPresented: $showGatewayConsent) {
            MeshGatewayConsentView(onAccept: {
                vm.enableGatewayMode(consentGranted: true)
                showGatewayConsent = false
            }, onDecline: {
                showGatewayConsent = false
            })
        }
    }
}

// MARK: - Mesh Invitation Banner (incoming connection request)

struct MeshInvitationBanner: View {
    @EnvironmentObject var vm: RnetViewModel
    let peer: AnyObject  // MCPeerID — erased for preview compatibility

    var peerName: String {
        (peer as? NSObject).flatMap { Mirror(reflecting: $0).children.first(where: { $0.label == "displayName" })?.value as? String } ?? "Unknown Peer"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Mesh connection request from \"\(peerName)\"")
                .font(.subheadline)
                .foregroundStyle(.primary)

            Text("Allow this device to join your mesh cluster? All traffic remains end-to-end encrypted.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Button("Allow") { vm.mesh.acceptInvitation() }
                    .buttonStyle(.borderedProminent)
                Button("Deny") { vm.mesh.declineInvitation() }
                    .buttonStyle(.bordered)
                    .foregroundStyle(.red)
            }
        }
        .padding(10)
        .background(Color.orange.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Gateway Consent Sheet

struct MeshGatewayConsentView: View {
    var onAccept: () -> Void
    var onDecline: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Act as Mesh Gateway?")
                        .font(.title2.bold())

                    Text("RNET will allow nearby devices in the local mesh cluster to route their traffic through this device's internet connection. All relayed traffic is end-to-end encrypted.")
                        .font(.body)

                    VStack(alignment: .leading, spacing: 4) {
                        Label("No traffic content is inspected", systemImage: "lock.shield")
                        Label("Only aggregate byte counts are logged locally", systemImage: "chart.bar")
                        Label("You can disable this at any time", systemImage: "xmark.circle")
                    }
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                    Spacer()

                    Button(action: onAccept) {
                        Text("I Understand — Enable Gateway")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    Button(action: onDecline) {
                        Text("Cancel")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                .padding()
            }
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

// MARK: - Shared card container

struct RnetCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding()
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}

// MARK: - MetricRow

struct MetricRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline.monospacedDigit())
        }
    }
}
