using System;

namespace DuoUniversal
{
    public class DuoException : Exception
    {
        public DuoException(string message) : base(message)
        {
        }

        public DuoException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}
