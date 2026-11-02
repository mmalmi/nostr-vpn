#if os(iOS)
import Foundation
import Intents
import UIKit

/// Shared by the app and share extension; suggestions contain device identities,
/// never file names or contents.
enum FileShareSuggestions {
    private static let recentKey = "file-recent-recipients"
    private static let identifierPrefix = "nvpn-files:"
    private static var defaults: UserDefaults? {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "NVPNAppGroupIdentifier") as? String else { return nil }
        return UserDefaults(suiteName: group)
    }

    static func migrateRecents() {
        guard let defaults, defaults.object(forKey: recentKey) == nil,
              let previous = UserDefaults.standard.stringArray(forKey: recentKey) else { return }
        defaults.set(previous, forKey: recentKey)
    }

    static func sorted(_ peers: [FileSharePeer]) -> [FileSharePeer] {
        let recent = defaults?.stringArray(forKey: recentKey) ?? []
        return peers.sorted {
            let a = recent.firstIndex(of: $0.npub) ?? Int.max
            let b = recent.firstIndex(of: $1.npub) ?? Int.max
            return a == b ? $0.name.localizedStandardCompare($1.name) == .orderedAscending : a < b
        }
    }

    static func retain(_ peers: [FileSharePeer]) {
        guard let defaults else { return }
        let allowed = Set(peers.map(\.npub))
        let recent = defaults.stringArray(forKey: recentKey) ?? []
        let removed = recent.filter { !allowed.contains($0) }
        guard !removed.isEmpty else { return }
        defaults.set(recent.filter { allowed.contains($0) }, forKey: recentKey)
        INInteraction.delete(with: removed.map { identifierPrefix + $0 }, completion: nil)
    }

    static func record(_ peer: FileSharePeer) {
        let recent = defaults?.stringArray(forKey: recentKey) ?? []
        let updated = Array(([peer.npub] + recent.filter { $0 != peer.npub }).prefix(8))
        defaults?.set(updated, forKey: recentKey)
        let expired = recent.filter { !updated.contains($0) }
        if !expired.isEmpty { INInteraction.delete(with: expired.map { identifierPrefix + $0 }, completion: nil) }
        let recipient = INPerson(
            personHandle: INPersonHandle(value: peer.npub, type: .unknown),
            nameComponents: nil, displayName: peer.name,
            image: avatar(peer).pngData().map { INImage(imageData: $0) },
            contactIdentifier: nil, customIdentifier: peer.npub,
            isContactSuggestion: false, suggestionType: .instantMessageAddress
        )
        let intent = INSendMessageIntent(
            recipients: [recipient], outgoingMessageType: .outgoingMessageText,
            content: nil, speakableGroupName: nil,
            conversationIdentifier: identifierPrefix + peer.npub,
            serviceName: "Nostr VPN", sender: nil, attachments: nil
        )
        let interaction = INInteraction(intent: intent, response: nil)
        interaction.identifier = identifierPrefix + peer.npub
        interaction.groupIdentifier = "nvpn-files"
        interaction.direction = .outgoing
        interaction.donate(completion: nil)
    }

    static func recipient(for intent: INSendMessageIntent?, among peers: [FileSharePeer]) -> FileSharePeer? {
        guard let identifier = intent?.conversationIdentifier else { return nil }
        return peers.first { identifierPrefix + $0.npub == identifier }
    }

    /// Devices have no profile photos. Use a stable local monogram in both the
    /// destination list and iOS suggestions instead of fetching unrelated photos.
    static func avatar(_ peer: FileSharePeer) -> UIImage {
        let colors: [UIColor] = [.systemIndigo, .systemBlue, .systemTeal, .systemPurple, .systemOrange]
        let color = colors[peer.npub.utf8.reduce(0) { ($0 + Int($1)) % colors.count }]
        let words = peer.name.split(whereSeparator: \.isWhitespace)
        let initials = words.prefix(2).compactMap(\.first).map(String.init).joined().uppercased()
        let text = initials.isEmpty ? String(peer.npub.suffix(2)).uppercased() : initials
        let format = UIGraphicsImageRendererFormat()
        format.scale = 2
        return UIGraphicsImageRenderer(size: CGSize(width: 48, height: 48), format: format).image { _ in
            color.setFill()
            UIBezierPath(ovalIn: CGRect(x: 0, y: 0, width: 48, height: 48)).fill()
            let attributes: [NSAttributedString.Key: Any] = [
                .font: UIFont.systemFont(ofSize: 18, weight: .semibold), .foregroundColor: UIColor.white,
            ]
            let size = (text as NSString).size(withAttributes: attributes)
            (text as NSString).draw(at: CGPoint(x: (48 - size.width) / 2, y: (48 - size.height) / 2), withAttributes: attributes)
        }
    }
}
#endif
