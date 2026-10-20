using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace EncryptionExample
{
    /// <summary>RSA key pairs of the servers, stored as PEM files.</summary>
    public static class RsaKeys
    {
        public const string OaepName = "RSA-OAEP-SHA256";

        /// <summary>RSA-OAEP with SHA-256 for both the label hash and MGF1, same as .NET's <c>RSAEncryptionPadding.OaepSHA256</c>.</summary>
        public static OaepEncoding CreateOaep() => new OaepEncoding(new RsaEngine(), new Sha256Digest());

        public static AsymmetricCipherKeyPair Generate()
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            return generator.GenerateKeyPair();
        }

        public static void Save(AsymmetricCipherKeyPair pair, string privateKeyPath, string publicKeyPath)
        {
            WritePem(privateKeyPath, pair.Private);
            WritePem(publicKeyPath, pair.Public);
        }

        public static AsymmetricCipherKeyPair LoadPrivate(string path)
        {
            using (var reader = File.OpenText(path))
                return (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
        }

        public static AsymmetricKeyParameter LoadPublic(string path)
        {
            using (var reader = File.OpenText(path))
                return (AsymmetricKeyParameter)new PemReader(reader).ReadObject();
        }

        /// <summary>Identifies a public key in the key table.</summary>
        /// <remarks>
        /// Hashes the DER SubjectPublicKeyInfo, i.e. the body of a "PUBLIC KEY" PEM. Every side must hash
        /// exactly this encoding, or the lookup misses.
        /// </remarks>
        public static string PubKeyHash(AsymmetricKeyParameter publicKey)
        {
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded();
            return Convert.ToBase64String(DigestUtilities.CalculateDigest("SHA-256", spki));
        }

        private static void WritePem(string path, object key)
        {
            using (var writer = new StreamWriter(path))
                new PemWriter(writer).WriteObject(key);
        }
    }
}
