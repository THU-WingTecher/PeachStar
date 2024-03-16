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
//   Michael Eddington (mike@dejavusecurity.com)

// $Id$

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;
using System.Runtime.Remoting.Channels.Ipc;
using System.Threading;

using Peach.Core.Publishers.Com;

using NLog;

namespace Peach.Core.ComContainer
{
	public class Program
	{
		public static bool Shutdown = false;

		static void Main(string[] args)
		{
			var ipcChannelName = "Peach_Com_Container";

			if (args.Length == 1 && args[0] == "-h")
			{
				Console.WriteLine("> Peach.Core.ComContainer");
				Console.WriteLine("> Copyright (c) Deja vu Security\n");

				Console.WriteLine("Syntax:");
				Console.WriteLine(" Peach.Core.ComContainer.exe IPC_CHANNEL_NAME\n\n");

				return;
			}

			if (args.Length == 1)
				ipcChannelName = args[0];

			IpcChannel ipcChannel = new IpcChannel(ipcChannelName);
			ChannelServices.RegisterChannel(ipcChannel, false);

			try
			{
				Type commonInterfaceType = typeof(Peach.Core.Agent.Monitors.WindowsDebug.DebuggerInstance);

				RemotingConfiguration.RegisterWellKnownServiceType(
					typeof(ComContainer), "PeachComContainer", WellKnownObjectMode.Singleton);

				while (!Shutdown)
					Thread.Sleep(200);
			}
			finally
			{
				ChannelServices.UnregisterChannel(ipcChannel);
			}
		}
	}
}
