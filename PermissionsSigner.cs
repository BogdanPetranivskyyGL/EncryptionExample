using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace EncryptionExample
{
    /// <summary>Signs and verifies <see cref="Permissions"/> with HMAC-SHA256.</summary>
    /// <remarks>
    /// The HMAC key is derived with HKDF from the file's AES key, so only someone who can open the file (a server)
    /// can produce a valid signature, and a signature from one file does not fit another.
    /// </remarks>
    public static class PermissionsSigner
    {
        private static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("EncryptionExample/permissions/hmac-sha256/v1");

        public static Permissions Sign(PermissionsData data, byte[] fileKey) =>
            new Permissions { Data = data, Sig = Convert.ToBase64String(ComputeMac(data, fileKey)) };

        public static bool Verify(Permissions permissions, byte[] fileKey)
        {
            if (permissions?.Data == null || string.IsNullOrEmpty(permissions.Sig))
                return false;

            byte[] sig;
            try
            {
                sig = Convert.FromBase64String(permissions.Sig);
            }
            catch (FormatException)
            {
                return false;
            }

            return Arrays.FixedTimeEquals(sig, ComputeMac(permissions.Data, fileKey));
        }

        private static byte[] ComputeMac(PermissionsData data, byte[] fileKey)
        {
            var hmac = new HMac(new Sha256Digest());
            hmac.Init(new KeyParameter(DeriveMacKey(fileKey)));

            var bytes = SignedBytes(data);
            hmac.BlockUpdate(bytes, 0, bytes.Length);

            var mac = new byte[hmac.GetMacSize()];
            hmac.DoFinal(mac, 0);
            return mac;
        }

        // The AES key is already uniformly random, so no salt is needed; the info string keeps the HMAC key
        // separate from the key that encrypts the content.
        private static byte[] DeriveMacKey(byte[] fileKey)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(fileKey, null, HkdfInfo));

            var key = new byte[32];
            hkdf.GenerateBytes(key, 0, key.Length);
            return key;
        }

        // Signs a fixed text layout rather than the JSON: JSON text depends on serializer settings (spacing, property
        // order, escaping), and a re-serialized but unchanged object must still verify.
        private static byte[] SignedBytes(PermissionsData data)
        {
            var text = new StringBuilder()
                .Append("permissions-v1\n")
                .Append(data.Revision.ToString(CultureInfo.InvariantCulture)).Append('\n')
                .Append(data.AccessType.ToString()).Append('\n');

            foreach (var user in data.Users ?? new List<string>())
                text.Append(user).Append('\n');

            return Encoding.UTF8.GetBytes(text.ToString());
        }
    }
}
