﻿
//
// Copyright (c) Michael Eddington
//
// Permission is hereby granted, free of charge, to any person obtaining a copy 
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights 
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
// copies of the Software, and to permit persons to whom the Software is 
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in	
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Authors:
//   Mikhail Davidov (sirus@haxsys.net)

// $Id$

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using Peach.Core.Dom;
using Peach.Core.IO;
using System.Linq;

namespace Peach.Core.Transformers.Encode
{
    [Description("Encode on output from a dot notation string to a 4 byte octet representaiton.")]
    [Transformer("Ipv4StringToOctet", true)]
    [Transformer("encode.Ipv4StringToOctet")]
    [Serializable]
    public class Ipv4StringToOctet : Transformer
    {
        public Ipv4StringToOctet(Dictionary<string,Variant>  args) : base(args)
        {
        }

        protected override BitStream internalEncode(BitStream data)
        {
            string sip = Encoding.ASCII.GetString(data.Value);
			IPAddress ip;

            if(sip.Count(c => c == '.') != 3 || !IPAddress.TryParse(sip, out ip))
				throw new PeachException("Error, can't transform IP to bytes, '{0}' is not a valid IP address.".Fmt(sip));

            return new BitStream(ip.GetAddressBytes());
        }

        protected override BitStream internalDecode(BitStream data)
        {
			var buf = data.Value;

			if (buf.Length != 4)
				throw new PeachException("Error, can't transform bytes to IP, expected 4 bytes but got {0} bytes.".Fmt(buf.Length));

			IPAddress ip = new IPAddress(buf);

			return new BitStream(Encoding.ASCII.GetBytes(ip.ToString()));
        }
    }
}

// end