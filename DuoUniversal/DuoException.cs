// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
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
