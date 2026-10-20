using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace EncryptionExample
{
    /// <summary>Who may open the file. Stored in plain text, signed with a key derived from the file key.</summary>
    public sealed class Permissions
    {
        public PermissionsData Data { get; set; }

        /// <summary>Base64 HMAC-SHA256 over <see cref="Data"/>, see <see cref="PermissionsSigner"/>.</summary>
        public string Sig { get; set; }
    }

    public sealed class PermissionsData
    {
        /// <summary>Grows with every change, so a server that remembers the last one can refuse an older signed copy.</summary>
        public long Revision { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public AccessType AccessType { get; set; }

        /// <summary>Upper-invariant emails, sorted; used only with <see cref="EncryptionExample.AccessType.SpecificUsers"/>.</summary>
        public List<string> Users { get; set; } = new List<string>();

        public static PermissionsData Create(
            long revision,
            AccessType accessType,
            IEnumerable<string> users = null) =>
            new PermissionsData
            {
                Revision = revision,
                AccessType = accessType,
                Users = (users ?? Enumerable.Empty<string>())
                    .Select(user => user.Trim().ToUpperInvariant())
                    .Distinct()
                    .OrderBy(user => user, StringComparer.Ordinal)
                    .ToList(),
            };

        /// <param name="userEmail">The signed-in user's email; <c>null</c> for an anonymous request.</param>
        public bool Allows(string userEmail)
        {
            switch (AccessType)
            {
                case AccessType.All:
                    return true;
                case AccessType.Authorized:
                    return userEmail != null;
                case AccessType.SpecificUsers:
                    return userEmail != null && Users.Contains(userEmail.Trim().ToUpperInvariant());
                default:
                    return false;
            }
        }
    }

    public enum AccessType
    {
        /// <summary>Anyone, including anonymous requests.</summary>
        All,

        /// <summary>Any signed-in user.</summary>
        Authorized,

        /// <summary>Only the users listed in <see cref="PermissionsData.Users"/>.</summary>
        SpecificUsers,
    }
}
