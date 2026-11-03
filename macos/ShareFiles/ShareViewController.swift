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
    @Published var progress = 0.0
    @Published var progressText = "Preparing files…"
    @Published var search = ""
    private var preparation: FilePreparation?
    var summary: String {
        let providers = (context?.inputItems as? [NSExtensionItem] ?? []).flatMap { $0.attachments ?? [] }
        let name = providers.first?.suggestedName ?? "\(providers.count) files"
        return providers.count > 1 && providers.first?.suggestedName != nil ? "\(name) + \(providers.count - 1)" : name
    }
    var visiblePeers: [FileSharePeer] {
        search.isEmpty ? peers : peers.filter { "\($0.name) \($0.detail ?? "")".localizedCaseInsensitiveContains(search) }
    }
    private let context: NSExtensionContext?
    init(context: NSExtensionContext?) {
        self.context = context
        if let root = MacShareStorage.root, let data = try? Data(contentsOf: root.appendingPathComponent("file-share-peers.json")) {
            peers = (try? JSONDecoder().decode([FileSharePeer].self, from: data)) ?? []
        }
    }
    func cancel() {
        if busy { preparation?.cancel(); progressText = "Cancelling…" }
        else { context?.completeRequest(returningItems: nil) }
    }
    func send(to peer: FileSharePeer) {
        guard !busy, let root = MacShareStorage.root else { return }
        let providers = (context?.inputItems as? [NSExtensionItem] ?? []).flatMap { $0.attachments ?? [] }
        guard !providers.isEmpty, providers.count <= 32 else { error = "Choose up to 32 files."; return }
        busy = true
        let preparation = FilePreparation()
        self.preparation = preparation
        preparation.progress = { [weak self] count, total, name in
            Task { @MainActor in
                self?.progress = total == 0 ? 0 : Double(count) / Double(total)
                self?.progressText = "Preparing \(name) · \(FileTransferPresentation.bytes(count)) of \(FileTransferPresentation.bytes(total))"
            }
        }
        Task {
            var batches: [URL] = []
            do {
                var paths: [String] = []
                for provider in providers {
                    let batch = try FileTransferStorage.makeBatch(in: root)
                    batches.append(batch)
                    paths.append(try await FileTransferStorage.copyProvider(provider, to: batch, preparation: preparation))
                }
                try preparation.checkCancellation()
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
                if error is CancellationError { context?.completeRequest(returningItems: nil) }
                else { self.error = error.localizedDescription }
                busy = false
                self.preparation = nil
            }
        }
    }
}

struct MacFileShareView: View {
    @ObservedObject var model: MacFileShareModel
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Send files with nvpn").font(.title2)
            Text(model.summary).font(.callout).lineLimit(2)
            Text("Choose a device. You can follow the transfer in nvpn.").font(.caption).foregroundStyle(.secondary)
            if model.peers.isEmpty { Text("Open nvpn and link another device first.").foregroundStyle(.secondary) }
            if model.peers.count > 7 { TextField("Search devices", text: $model.search).textFieldStyle(.roundedBorder) }
            if !model.error.isEmpty { Text(model.error).foregroundStyle(.red) }
            if model.busy { ProgressView(model.progressText, value: model.progress).font(.caption) }
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(model.visiblePeers) { peer in
                        Button { model.send(to: peer) } label: {
                            HStack {
                                Image(systemName: "desktopcomputer")
                                VStack(alignment: .leading) {
                                    Text(peer.name)
                                    Text([peer.detail, peer.reachable == false ? "Offline — waits for a connection" : nil].compactMap { $0 }.joined(separator: " · "))
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                        }
                            .disabled(model.busy)
                    }
                }
            }
            HStack { Spacer(); Button("Cancel") { model.cancel() } }
        }.padding(20).frame(width: 340, height: 360)
    }
}
