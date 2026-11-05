import SwiftUI

/// ServerSetupView — first-run onboarding sheet.
///
/// Presented when no relay server has been configured yet.
/// The transport engine will not start until the user saves a valid endpoint.
/// See deploy/ in the repository root for a one-command relay server setup.
struct ServerSetupView: View {

    @Environment(\.dismiss) private var dismiss

    @State private var host: String = ""
    @State private var portText: String = "7777"
    @State private var hostError = false
    @State private var portError = false

    var onSaved: (() -> Void)?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("RNET Setup")
                            .font(.title2.bold())
                        Text("Enter the address of your RNET relay server.\nDeploy your own relay in one command — see the deploy/ directory in the repository.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
                .listRowBackground(Color.clear)

                Section("Relay server") {
                    VStack(alignment: .leading, spacing: 2) {
                        TextField("Host (domain or IP)", text: $host)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .keyboardType(.URL)
                            .onChange(of: host) { hostError = false }
                        if hostError {
                            Text("Enter a valid hostname or IP address")
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        TextField("UDP port", text: $portText)
                            .keyboardType(.numberPad)
                            .onChange(of: portText) { portError = false }
                        if portError {
                            Text("Port must be 1–65535")
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                    }
                }

                Section {
                    Button(action: save) {
                        HStack {
                            Spacer()
                            Text("Save and continue")
                                .bold()
                            Spacer()
                        }
                    }
                }

                Section {
                    Text("No relay yet? Run docker compose up in the deploy/ directory on any Linux VPS to start your relay server in under a minute.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .listRowBackground(Color.clear)
            }
            .navigationTitle("Server Setup")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func save() {
        let trimHost = host.trimmingCharacters(in: .whitespaces)
        let port = Int(portText.trimmingCharacters(in: .whitespaces))

        hostError = trimHost.isEmpty
        portError = port == nil || port! < 1 || port! > 65535

        guard !hostError && !portError else { return }

        ServerConfig.save(host: trimHost, port: port!)
        onSaved?()
        dismiss()
    }
}

#Preview {
    ServerSetupView()
}
