using System.Security.Cryptography;
using System.Text;

namespace DuoUniversal
{

    internal class Utils
    {
        internal static string GenerateRandomString(int length)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                StringBuilder sb = new StringBuilder();
                while (sb.Length < length)
                {
                    sb.Append(GenerateValidChar(rng));
                }
                return sb.ToString().Substring(0, length);
            }
        }

        private static char GenerateValidChar(RNGCryptoServiceProvider rng)
        {
            byte[] b = new byte[1];
            char c;
            do
            {
                rng.GetBytes(b);
                c = (char)b[0];
            } while (!char.IsLetterOrDigit(c));

            return c;
        }
    }
}
