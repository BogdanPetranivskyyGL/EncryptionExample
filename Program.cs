using System;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;

namespace EncryptionExample
{
    internal static class Program
    {
        private const string KeysDirectory = "keys";

        private static int Main(string[] args)
        {
            try
            {
                switch (args.FirstOrDefault())
                {
                    case "keygen" when args.Length == 2:
                        KeyGen(args[1]);
                        return 0;
                    case "encrypt" when args.Length == 3 || args.Length == 4:
                        Encrypt(args[1], args[2], args.ElementAtOrDefault(3) ?? "specific");
                        return 0;
                    case "decrypt" when args.Length == 4 || args.Length == 5:
                        Decrypt(
                            args[1],
                            args[2],
                            args[3],
                            args.ElementAtOrDefault(4));
                        return 0;
                    case "demo":
                    case null:
                        Demo();
                        return 0;
                    default:
                        Console.WriteLine("Usage:");
                        Console.WriteLine("  EncryptionExample demo");
                        Console.WriteLine("  EncryptionExample keygen <server>");
                        Console.WriteLine("  EncryptionExample encrypt <input> <output.json> [all|authorized|specific[:<email>,<email>...]]");
                        Console.WriteLine("  EncryptionExample decrypt <input.json> <server> <output> [<signed-in user email>]");
                        return 1;
                }
            }
            catch (Exception ex) when (IsRefusal(ex))
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
        }

        /// <summary>The whole flow in memory: three servers, one client save, servers asked for the key by different users.</summary>
        private static void Demo()
        {
            var servers = new[] { "server-a", "server-b", "server-c" }
                .ToDictionary(name => name, name => RsaKeys.Generate());
            var serverA = new Server(servers["server-a"]);
            var serverC = new Server(servers["server-c"]);

            var content = Encoding.UTF8.GetBytes("<EasSection>secret settings</EasSection>");
            var file = Client.Save(
                content,
                AccessType.SpecificUsers,
                new[] { "alice@example.com" },
                servers.Values.Select(keys => keys.Public));
            Console.WriteLine($"Saved by {Client.GetEmail()}:");
            Console.WriteLine(JsonConvert.SerializeObject(file, Formatting.Indented));
            Console.WriteLine();

            Console.WriteLine("Sent to the key endpoint on open:");
            Console.WriteLine(JsonConvert.SerializeObject(new { file.KeyTable, file.Permissions }, Formatting.Indented));
            Console.WriteLine();

            TryOpen("server-a, user@example.com", file, serverA, "user@example.com");
            TryOpen("server-c, ALICE@example.com", file, serverC, "ALICE@example.com");
            TryOpen("server-c, carol@example.com", file, serverC, "carol@example.com");
            TryOpen("server-c, anonymous", file, serverC, null);
            TryOpen("unknown server", file, new Server(RsaKeys.Generate()), "user@example.com");

            var forged = Copy(file);
            forged.Permissions.Data.AccessType = AccessType.All;
            TryOpen("AccessType switched to All without re-signing", forged, serverA, null);

            var tampered = Copy(file);
            var data = Convert.FromBase64String(tampered.EncryptedData);
            data[0] ^= 1;
            tampered.EncryptedData = Convert.ToBase64String(data);
            TryOpen("one bit of EncryptedData flipped", tampered, serverA, "user@example.com");
        }

        private static void TryOpen(
            string title,
            EncryptedFile file,
            Server server,
            string signedInUser)
        {
            server.CurrentUserEmail = signedInUser;
            try
            {
                Console.WriteLine($"  {title}: {Encoding.UTF8.GetString(Client.Open(file, server))}");
            }
            catch (Exception ex) when (IsRefusal(ex))
            {
                Console.WriteLine($"  {title}: refused - {ex.Message}");
            }
        }

        private static bool IsRefusal(Exception ex) =>
            ex is InvalidOperationException || ex is UnauthorizedAccessException || ex is InvalidCipherTextException;

        private static EncryptedFile Copy(EncryptedFile file) =>
            JsonConvert.DeserializeObject<EncryptedFile>(JsonConvert.SerializeObject(file));

        private static void KeyGen(string server)
        {
            Directory.CreateDirectory(KeysDirectory);
            RsaKeys.Save(RsaKeys.Generate(), PrivateKeyPath(server), PublicKeyPath(server));
            Console.WriteLine($"Created {PrivateKeyPath(server)} and {PublicKeyPath(server)}");
        }

        /// <summary>Client save: encrypts for every public key found in the keys directory.</summary>
        private static void Encrypt(
            string inputPath,
            string outputPath,
            string access)
        {
            var publicKeys = Directory.GetFiles(KeysDirectory, "*.public.pem").Select(RsaKeys.LoadPublic).ToList();
            if (publicKeys.Count == 0)
                throw new InvalidOperationException($"No *.public.pem in '{KeysDirectory}'; run keygen first.");

            var parts = access.Split(new[] { ':' }, 2);
            var accessType = parts[0].ToLowerInvariant() == "all" ? AccessType.All
                : parts[0].ToLowerInvariant() == "authorized" ? AccessType.Authorized
                : AccessType.SpecificUsers;
            var users = parts.Length == 2 ? parts[1].Split(',') : new string[0];

            var file = Client.Save(
                File.ReadAllBytes(inputPath),
                accessType,
                users,
                publicKeys);
            File.WriteAllText(outputPath, JsonConvert.SerializeObject(file, Formatting.Indented));
            Console.WriteLine($"Saved by {Client.GetEmail()} for {publicKeys.Count} server(s) into {outputPath}");
        }

        private static void Decrypt(
            string inputPath,
            string server,
            string outputPath,
            string signedInUser)
        {
            var file = JsonConvert.DeserializeObject<EncryptedFile>(File.ReadAllText(inputPath));
            var keyServer = new Server(RsaKeys.LoadPrivate(PrivateKeyPath(server))) { CurrentUserEmail = signedInUser };
            File.WriteAllBytes(outputPath, Client.Open(file, keyServer));
            Console.WriteLine($"Opened via {server} for {signedInUser ?? "anonymous"} into {outputPath}");
        }

        private static string PrivateKeyPath(string server) => Path.Combine(KeysDirectory, server + ".private.pem");

        private static string PublicKeyPath(string server) => Path.Combine(KeysDirectory, server + ".public.pem");
    }
}
