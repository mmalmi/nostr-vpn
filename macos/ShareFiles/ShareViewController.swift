import AppKit
import SwiftUI
import UniformTypeIdentifiers

final class ShareViewController: NSViewController {
    override func loadView() {
        let model = MacFileShareModel(context: extensionContext)
        view = NSHostingView(rootView: MacFileShareView(model: model))
        preferredContentSize = NSSize(width: 340, height: 360)
    }
}

@MainActor
final class MacFileShareModel: ObservableObject {
    @Published var peers: [FileSharePeer] = []
    @Published var busy = false
    @Published var error = ""
    private let context: NSExtensionContext?
    init(context: NSExtensionContext?) {
        self.context = context
        if let root = MacShareStorage.root, let data = try? Data(contentsOf: root.appendingPathComponent("file-share-peers.json")) {
            peers = (try? JSONDecoder().decode([FileSharePeer].self, from: data)) ?? []
        }
    }
    func cancel() { if !busy { context?.completeRequest(returningItems: nil) } }
    func send(to peer: FileSharePeer) {
        guard !busy, let root = MacShareStorage.root else { return }
        let providers = (context?.inputItems as? [NSExtensionItem] ?? []).flatMap { $0.attachments ?? [] }
        guard !providers.isEmpty, providers.count <= 32 else { error = "Choose up to 32 files."; return }
        busy = true
        Task {
            var batches: [URL] = []
            do {
                var paths: [String] = []
                for provider in providers {
                    let batch = try FileTransferStorage.makeBatch(in: root)
                    batches.append(batch)
                    paths.append(try await FileTransferStorage.copyProvider(provider, to: batch))
                }
                let requests = root.appendingPathComponent("requests", isDirectory: true)
                try FileManager.default.createDirectory(at: requests, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                let id = UUID().uuidString
                let data = try JSONEncoder().encode(MacShareRequest(id: id, npub: peer.npub, paths: paths))
                guard data.count <= 65536 else { throw CocoaError(.fileWriteOutOfSpace) }
                let request = requests.appendingPathComponent("\(id).json")
                try data.write(to: request, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: request.path)
                NSWorkspace.shared.open(URL(string: "nvpn://file-share")!)
                context?.completeRequest(returningItems: nil)
            } catch {
                for batch in batches { try? FileManager.default.removeItem(at: batch) }
                self.error = error.localizedDescription
                busy = false
            }
        }
    }
}

struct MacFileShareView: View {
    @ObservedObject var model: MacFileShareModel
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Send files with nvpn").font(.title2)
            if model.peers.isEmpty { Text("Open nvpn and connect to choose a device.").foregroundStyle(.secondary) }
            if !model.error.isEmpty { Text(model.error).foregroundStyle(.red) }
            if model.busy { ProgressView("Preparing files…") }
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(model.peers) { peer in
                        Button { model.send(to: peer) } label: { Label(peer.name, systemImage: "paperplane.fill").frame(maxWidth: .infinity, alignment: .leading) }
                            .disabled(model.busy)
                    }
                }
            }
            HStack { Spacer(); Button("Cancel") { model.cancel() }.disabled(model.busy) }
        }.padding(20).frame(width: 340, height: 360)
    }
}
