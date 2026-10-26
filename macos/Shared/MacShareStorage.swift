import Foundation

struct MacShareRequest: Codable {
    var id: String
    var npub: String
    var paths: [String]
    var stagedPaths: [String]? = nil
}

enum MacShareStorage {
    static var root: URL? {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "NVPNShareAppGroup") as? String,
              !group.isEmpty, !group.contains("$(") else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
    }
}
