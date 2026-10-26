import UIKit
import UniformTypeIdentifiers

final class ShareViewController: UITableViewController {
    private var peers: [FileSharePeer] = []
    private var sending = false
    private var supportDir: URL? {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "NVPNAppGroupIdentifier") as? String else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)?
            .appendingPathComponent("Nostr VPN", isDirectory: true)
    }
    private var providers: [NSItemProvider] {
        (extensionContext?.inputItems as? [NSExtensionItem] ?? []).flatMap { $0.attachments ?? [] }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let header = UILabel()
        header.text = "Send files with nvpn"
        header.font = .preferredFont(forTextStyle: .title2)
        header.textAlignment = .center
        header.frame.size.height = 64
        tableView.tableHeaderView = header
        let cancel = UIButton(type: .system)
        cancel.setTitle("Cancel", for: .normal)
        cancel.addTarget(self, action: #selector(cancelSharing), for: .touchUpInside)
        cancel.frame.size.height = 52
        tableView.tableFooterView = cancel
        if let url = supportDir?.appendingPathComponent("file-share-peers.json"), let data = try? Data(contentsOf: url) {
            peers = (try? JSONDecoder().decode([FileSharePeer].self, from: data)) ?? []
        }
        if peers.isEmpty {
            let label = UILabel()
            label.text = "Open nvpn and connect to a network to choose a device."
            label.numberOfLines = 0
            label.textAlignment = .center
            tableView.backgroundView = label
        }
    }

    @objc private func cancelSharing() {
        guard !sending else { return }
        extensionContext?.completeRequest(returningItems: nil)
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { peers.count }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.textLabel?.text = peers[indexPath.row].name
        cell.imageView?.image = UIImage(systemName: "paperplane.fill")
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        guard !sending, let supportDir else { return }
        let peer = peers[indexPath.row]
        let items = providers
        guard !items.isEmpty, items.count <= 32 else { showError("Choose up to 32 files."); return }
        sending = true
        tableView.isUserInteractionEnabled = false
        let progress = UIActivityIndicatorView(style: .large)
        progress.startAnimating()
        tableView.backgroundView = progress
        Task {
            var batches: [URL] = []
            do {
                var paths: [String] = []
                for provider in items {
                    let destination = try FileTransferStorage.makeBatch(in: supportDir)
                    batches.append(destination)
                    let path = try await FileTransferStorage.copyProvider(provider, to: destination)
                    paths.append(path)
                }
                try FileTransferStorage.enqueue(paths: paths, npub: peer.npub, in: supportDir)
                let alert = UIAlertController(title: "Files queued", message: "They’ll send while nvpn is connected.", preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "Done", style: .default) { [weak self] _ in
                    self?.extensionContext?.completeRequest(returningItems: nil)
                })
                present(alert, animated: true)
            } catch {
                for batch in batches { try? FileManager.default.removeItem(at: batch) }
                sending = false
                tableView.isUserInteractionEnabled = true
                tableView.backgroundView = nil
                showError(error.localizedDescription)
            }
        }
    }

    private func showError(_ message: String) {
        let alert = UIAlertController(title: "Could not send files", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}
