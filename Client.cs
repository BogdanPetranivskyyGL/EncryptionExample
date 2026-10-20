using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace EncryptionExample
{
    /// <summary>The client app: encrypts on save, asks a server for the key on open.</summary>
    public static class Client
    {
        private const int CurrentVersion = 1;
        private const string AesGcm = "AES-256-GCM";

        /// <summary>Stand-in for the email of the user signed in to the client app.</summary>
        public static string GetEmail() => "user@example.com";

        /// <summary>Encrypts <paramref name="content"/> so that any of <paramref name="serverPublicKeys"/> can hand out its key.</summary>
        /// <param name="users">Who else may open the file; the current user is always added.</param>
        public static EncryptedFile Save(
            byte[] content,
            AccessType accessType,
            IEnumerable<string> users,
            IEnumerable<AsymmetricKeyParameter> serverPublicKeys)
        {
            var random = new SecureRandom();
            var key = new byte[32];
            var iv = new byte[12];
            random.NextBytes(key);
            random.NextBytes(iv);

            var permissions = PermissionsData.Create(1, accessType, users.Concat(new[] { GetEmail() }));
            var file = new EncryptedFile
            {
                Version = CurrentVersion,
                Algorithm = AesGcm,
                KeyWrap = RsaKeys.OaepName,
                IV = Convert.ToBase64String(iv),
                Permissions = PermissionsSigner.Sign(permissions, key),
            };
            file.EncryptedData = Convert.ToBase64String(ProcessAesGcm(true, key, iv, HeaderAad(file), content));

            foreach (var publicKey in serverPublicKeys)
            {
                var rsa = RsaKeys.CreateOaep();
                rsa.Init(true, publicKey);
                file.KeyTable.Add(new KeyTableEntry
                {
                    PubKeyHash = RsaKeys.PubKeyHash(publicKey),
                    Key = Convert.ToBase64String(rsa.ProcessBlock(key, 0, key.Length)),
                });
            }

            return file;
        }

        /// <summary>Gets the file key from <paramref name="server"/> and decrypts the content locally.</summary>
        /// <exception cref="InvalidOperationException">The format is unknown, or the server refused the request.</exception>
        /// <exception cref="UnauthorizedAccessException">The server does not let the current user open the file.</exception>
        /// <exception cref="InvalidCipherTextException">The content was modified.</exception>
        public static byte[] Open(EncryptedFile file, Server server)
        {
            if (file.Version != CurrentVersion || file.Algorithm != AesGcm || file.KeyWrap != RsaKeys.OaepName)
                throw new InvalidOperationException($"Unsupported format: v{file.Version} {file.Algorithm} {file.KeyWrap}.");

            // Only the key table and the permissions go to the server; the content never leaves the client.
            var key = Convert.FromBase64String(server.GetKey(file.KeyTable, file.Permissions));

            return ProcessAesGcm(
                false,
                key,
                Convert.FromBase64String(file.IV),
                HeaderAad(file),
                Convert.FromBase64String(file.EncryptedData));
        }

        // Authenticated with the content, so a downgraded header fails decryption.
        private static byte[] HeaderAad(EncryptedFile file) =>
            Encoding.UTF8.GetBytes($"{file.Version}|{file.Algorithm}|{file.KeyWrap}");

        private static byte[] ProcessAesGcm(
            bool encrypt,
            byte[] key,
            byte[] iv,
            byte[] aad,
            byte[] input)
        {
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, iv, aad));

            var output = new byte[gcm.GetOutputSize(input.Length)];
            var length = gcm.ProcessBytes(input, 0, input.Length, output, 0);
            gcm.DoFinal(output, length);
            return output;
        }
    }
}
