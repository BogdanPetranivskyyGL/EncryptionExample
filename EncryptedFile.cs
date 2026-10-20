using System.Collections.Generic;

namespace EncryptionExample
{
    /// <summary>The saved file: content encrypted once, its key wrapped for every server.</summary>
    public sealed class EncryptedFile
    {
        public int Version { get; set; }

        public string Algorithm { get; set; }

        public string KeyWrap { get; set; }

        /// <summary>One entry per server; a server finds its own by <see cref="KeyTableEntry.PubKeyHash"/>.</summary>
        public List<KeyTableEntry> KeyTable { get; set; } = new List<KeyTableEntry>();

        public Permissions Permissions { get; set; }

        /// <summary>AES-GCM nonce, 12 bytes. Not secret, so it is stored as is, once for the whole file.</summary>
        public string IV { get; set; }

        /// <summary>Ciphertext followed by the 16-byte GCM authentication tag.</summary>
        public string EncryptedData { get; set; }
    }

    public sealed class KeyTableEntry
    {
        /// <summary>Base64 SHA-256 of the server's public key (DER SubjectPublicKeyInfo).</summary>
        public string PubKeyHash { get; set; }

        /// <summary>The file's AES key, encrypted with this server's public key (RSA-OAEP-SHA256).</summary>
        public string Key { get; set; }
    }
}
