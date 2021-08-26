using System;

namespace DuoUniversal
{
    public class DuoException : Exception
    {
        internal DuoException(string message) : base(message)
        {
        }

        internal DuoException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}
