import Foundation
import Security

final class SecretManager {

    static let shared = SecretManager()

    private let account = "com.miapp.privateKey"
    private let service = "com.miapp.secrets"

    private var sessionAnchor: String?

    private init() {}

    func storeSecret(_ secret: String) {
        let data = secret.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecValueData as String: data
        ]

        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)

        self.sessionAnchor = secret
    }

    func loadSecret() -> String? {
        if let key = sessionAnchor {
            return key
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess,
              let data = item as? Data,
              let secret = String(data: data, encoding: .utf8) else {
            return nil
        }

        self.sessionAnchor = secret
        return secret
    }
}
