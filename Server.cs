using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Crypto;

namespace EncryptionExample
{
    /// <summary>One ASP.NET MVC server; hands out a file's symmetric key to users the permissions allow.</summary>
    public sealed class Server
    {
        private readonly AsymmetricCipherKeyPair _keys;
        private readonly string _pubKeyHash;

        public Server(AsymmetricCipherKeyPair keys)
        {
            _keys = keys ?? throw new ArgumentNullException(nameof(keys));
            _pubKeyHash = RsaKeys.PubKeyHash(keys.Public);
        }

        /// <summary>Stand-in for the request's signed-in user; <c>null</c> for an anonymous request.</summary>
        public string CurrentUserEmail { get; set; }

        /// <summary>The endpoint: returns the file's symmetric key, base64.</summary>
        /// <exception cref="InvalidOperationException">
        /// The key table has no row for this server, or the permissions are not validly signed.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">The permissions do not let the current user open the file.</exception>
        public string GetKey(List<KeyTableEntry> keyTable, Permissions permissions)
        {
            var entry = keyTable?.FirstOrDefault(e => e.PubKeyHash == _pubKeyHash)
                ?? throw new InvalidOperationException("The file is not encrypted for this server's key.");

            // The HMAC key is derived from the file key, so the key is unwrapped first, but it leaves the server only
            // after both checks pass.
            var rsa = RsaKeys.CreateOaep();
            rsa.Init(false, _keys.Private);
            var wrapped = Convert.FromBase64String(entry.Key);
            var key = rsa.ProcessBlock(wrapped, 0, wrapped.Length);

            if (!PermissionsSigner.Verify(permissions, key))
                throw new InvalidOperationException("The permissions signature is invalid.");

            if (!permissions.Data.Allows(CurrentUserEmail))
                throw new UnauthorizedAccessException($"'{CurrentUserEmail ?? "anonymous"}' may not open this file.");

            return Convert.ToBase64String(key);
        }
    }
}
