import SwiftUI

@main
struct RnetApp: App {
    @StateObject private var viewModel = RnetViewModel()
    private var telemetryTimer: Timer?

    init() {
        // Start mesh discovery on launch
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
                .onAppear {
                    viewModel.startMesh()
                    // Poll telemetry every 2 seconds
                    Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
                        Task { @MainActor in viewModel.syncTelemetry() }
                    }
                }
        }
    }
}
