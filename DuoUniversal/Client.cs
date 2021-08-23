using System;

namespace DuoUniversal
{
    public class Client
    {
        internal const int MINIMUM_STATE_LENGTH = 22;
        internal const int MAXIMUM_STATE_LENGTH = 1024;
        internal const int DEFAULT_STATE_LENGTH = 36;

        public static string GenerateState()
        {
            return GenerateState(DEFAULT_STATE_LENGTH);
        }

        public static string GenerateState(int length)
        {
            if (length > MAXIMUM_STATE_LENGTH || length < MINIMUM_STATE_LENGTH)
            {
                throw new ArgumentException("Invalid state length " + length + " requested.");
            }

            return Utils.GenerateRandomString(length);
        }
    }
}
