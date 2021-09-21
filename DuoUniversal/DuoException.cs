// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

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
