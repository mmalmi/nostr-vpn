import UIKit
import UniformTypeIdentifiers
import Intents

final class ShareViewController: UITableViewController, UISearchBarDelegate {
    private var peers: [FileSharePeer] = []
    private var search = ""
    private var sending = false
    private var queuedID: String?
    private var preparation: FilePreparation?
    private var observation: FileTransferObservation?
    private let statusLabel = UILabel()
    private let progress = UIProgressView(progressViewStyle: .default)
    private let closeButton = UIButton(type: .system)
    private let searchBar = UISearchBar()
    private var suggestedPeer: FileSharePeer?
    private var visiblePeers: [FileSharePeer] {
        search.isEmpty ? peers : peers.filter { "\($0.name) \($0.detail ?? "")".localizedCaseInsensitiveContains(search) }
    }
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
        if let url = supportDir?.appendingPathComponent("file-share-peers.json"), let data = try? Data(contentsOf: url) {
            peers = (try? JSONDecoder().decode([FileSharePeer].self, from: data)) ?? []
        }
        peers = FileShareSuggestions.sorted(peers)
        suggestedPeer = FileShareSuggestions.recipient(for: extensionContext?.intent as? INSendMessageIntent, among: peers)
        let title = UILabel()
        title.text = "Send files with nvpn"
        title.font = .preferredFont(forTextStyle: .title2)
        title.adjustsFontForContentSizeCategory = true
        title.numberOfLines = 0
        let summary = UILabel()
        let name = providers.first?.suggestedName
        summary.text = name.map { providers.count == 1 ? $0 : "\($0) + \(providers.count - 1)" } ?? "\(providers.count) files"
        summary.font = .preferredFont(forTextStyle: .body)
        summary.adjustsFontForContentSizeCategory = true
        summary.numberOfLines = 2
        statusLabel.font = .preferredFont(forTextStyle: .footnote)
        statusLabel.adjustsFontForContentSizeCategory = true
        statusLabel.textColor = .secondaryLabel
        statusLabel.numberOfLines = 0
        statusLabel.text = "Choose a device. The recipient will be asked to accept."
        progress.isHidden = true
        searchBar.placeholder = "Search devices"
        searchBar.delegate = self
        searchBar.isHidden = peers.count <= 7
        let stack = UIStackView(arrangedSubviews: [title, summary, statusLabel, progress, searchBar])
        if let suggestedPeer {
            let send = UIButton(type: .system)
            send.configuration = .filled()
            send.setTitle("Send to \(suggestedPeer.name)", for: .normal)
            send.accessibilityIdentifier = "file-share-suggested-send"
            send.addTarget(self, action: #selector(sendToSuggestion), for: .touchUpInside)
            stack.addArrangedSubview(send)
        }
        stack.axis = .vertical
        stack.spacing = 10
        stack.isLayoutMarginsRelativeArrangement = true
        stack.layoutMargins = UIEdgeInsets(top: 20, left: 20, bottom: 12, right: 20)
        stack.frame = CGRect(x: 0, y: 0, width: view.bounds.width, height: peers.count > 7 ? 225 : 175)
        tableView.tableHeaderView = stack
        closeButton.setTitle("Cancel", for: .normal)
        closeButton.addTarget(self, action: #selector(cancelSharing), for: .touchUpInside)
        closeButton.frame.size.height = 52
        tableView.tableFooterView = closeButton
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 68
        if peers.isEmpty {
            statusLabel.text = "Open nvpn and link another device first."
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        guard let header = tableView.tableHeaderView else { return }
        let size = header.systemLayoutSizeFitting(
            CGSize(width: tableView.bounds.width, height: UIView.layoutFittingCompressedSize.height),
            withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel)
        if abs(header.frame.height - size.height) > 1 || header.frame.width != tableView.bounds.width {
            header.frame.size = CGSize(width: tableView.bounds.width, height: size.height)
            tableView.tableHeaderView = header
        }
    }

    func searchBar(_ searchBar: UISearchBar, textDidChange searchText: String) {
        search = searchText
        tableView.reloadData()
    }

    @objc private func cancelSharing() {
        if sending && queuedID == nil {
            preparation?.cancel()
            statusLabel.text = "Cancelling…"
            return
        }
        observation?.stop()
        extensionContext?.completeRequest(returningItems: nil)
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { visiblePeers.count }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        let peer = visiblePeers[indexPath.row]
        cell.textLabel?.text = peer.name
        cell.detailTextLabel?.text = [peer.detail, peer.reachable == false ? "Offline — waits for a connection" : nil].compactMap { $0 }.joined(separator: " · ")
        cell.detailTextLabel?.numberOfLines = 2
        cell.imageView?.image = FileShareSuggestions.avatar(peer)
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        send(to: visiblePeers[indexPath.row])
    }

    @objc private func sendToSuggestion() {
        guard let suggestedPeer else { return }
        send(to: suggestedPeer)
    }

    private func send(to peer: FileSharePeer) {
        guard !sending, let supportDir else { return }
        let items = providers
        guard !items.isEmpty, items.count <= 32 else { showError("Choose up to 32 files."); return }
        sending = true
        tableView.allowsSelection = false
        searchBar.isUserInteractionEnabled = false
        progress.isHidden = false
        statusLabel.text = "Preparing files for \(peer.name)…"
        let preparation = FilePreparation()
        self.preparation = preparation
        preparation.progress = { [weak self, weak preparation] count, total, name in
            Task { @MainActor in
                guard let self, let preparation, self.preparation === preparation else { return }
                self.progress.progress = total == 0 ? 0 : Float(count) / Float(total)
                self.statusLabel.text = "Preparing \(name) · \(FileTransferPresentation.bytes(count)) of \(FileTransferPresentation.bytes(total))"
            }
        }
        Task { [self] in
            var batches: [URL] = []
            do {
                var paths: [String] = []
                for provider in items {
                    let destination = try FileTransferStorage.makeBatch(in: supportDir)
                    batches.append(destination)
                    paths.append(try await FileTransferStorage.copyProvider(provider, to: destination, preparation: preparation))
                }
                try preparation.checkCancellation()
                let id = try FileTransferStorage.enqueue(paths: paths, npub: peer.npub, in: supportDir)
                queuedID = id
                FileShareSuggestions.record(peer)
                self.preparation = nil
                statusLabel.text = "Queued for \(peer.name). If VPN is off, connect in nvpn. It can then send with the app closed."
                progress.progress = 0
                closeButton.setTitle("Done", for: .normal)
                observation = FileTransferObservation { [weak self] rows in
                    Task { @MainActor in
                        if let row = rows.first(where: { $0.id == id }) {
                            self?.statusLabel.text = [row.statusText, row.progressText, row.error]
                                .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
                            self?.progress.progress = row.totalBytes == 0 ? 0 : Float(row.transferredBytes) / Float(row.totalBytes)
                        } else if rows.contains(where: { $0.id == "service" && $0.status == "unavailable" }) {
                            self?.statusLabel.text = "File sending is unavailable. Your files are queued; reconnect in nvpn to try again."
                        }
                    }
                }
                observation?.start(in: supportDir)
            } catch {
                for batch in batches { try? FileManager.default.removeItem(at: batch) }
                sending = false
                self.preparation = nil
                tableView.allowsSelection = true
                searchBar.isUserInteractionEnabled = true
                progress.isHidden = true
                if error is CancellationError { extensionContext?.completeRequest(returningItems: nil) }
                else { showError(error.localizedDescription) }
            }
        }
    }

    private func showError(_ message: String) {
        let alert = UIAlertController(title: "Could not send files", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}
