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

// $Id$

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Peach.Core.UI.Windows
{
    internal static class HwndInterface
    {
        #region Windows
        public static List<IntPtr> EnumHwnds()
        {
            var parent = IntPtr.Zero;
            return EnumChildren(parent);
        }

        public static IntPtr GetHwnd(string windowText, string className)
        {
            return (IntPtr)FindWindow(className, windowText);
        }

        public static IntPtr GetHwndFromTitle(string windowText)
        {
            return (IntPtr)FindWindow(null, windowText);
        }

        public static IntPtr GetHwndFromClass(string className)
        {
            return (IntPtr)FindWindow(className, null);
        }

        public static bool ActivateWindow(IntPtr hwnd)
        {
            return SetForegroundWindow(hwnd);
        }

        public static bool MinimizeWindow(IntPtr hwnd)
        {
            return CloseWindow(hwnd);
        }
        #endregion

        #region Hwnd Attributes
        public static string GetHwndClassName(IntPtr hwnd)
        {
            var result = new StringBuilder(256);
            GetClassName(hwnd, result, result.MaxCapacity);
            return result.ToString();
        }
        public static int GetHwndTitleLength(IntPtr hwnd)
        {
            return GetWindowTextLength(hwnd);
        }
        public static string GetHwndTitle(IntPtr hwnd)
        {
            var length = GetHwndTitleLength(hwnd);
            var result = new StringBuilder(length + 1);
            GetWindowText(hwnd, result, result.Capacity);
            return result.ToString();
        }
        public static bool SetHwndTitle(IntPtr hwnd, string text)
        {
            return SetWindowText(hwnd, text);
        }
        public static string GetHwndText(IntPtr hwnd)
        {
            var len = (int)SendMessage(hwnd, (UInt32)WM.GETTEXTLENGTH, 0, 0) + 1;
            var sb = new StringBuilder(len);
            SendMessage(hwnd, (UInt32)WM.GETTEXT, (uint)len, sb);
            return sb.ToString();
        }
        public static void SetHwndText(IntPtr hwnd, string text)
        {
            SendMessage(hwnd, (UInt32)WM.SETTEXT, 0, text);
        }
        public static bool SetHwndPos(IntPtr hwnd, int x, int y)
        {
            return SetWindowPos(hwnd, IntPtr.Zero, x, y, 0, 0,
                         (uint)(PositioningFlags.SWP_NOSIZE | PositioningFlags.SWP_NOZORDER));
        }
        public static Point GetHwndPos(IntPtr hwnd)
        {
            var rect = new RECT();
            GetWindowRect(hwnd, out rect);
            var result = new Point(rect.Left, rect.Top);
            return result;
        }
        public static bool SetHwndSize(IntPtr hwnd, int w, int h)
        {
            return SetWindowPos(hwnd, IntPtr.Zero, 0, 0, w, h,
                         (uint)(PositioningFlags.SWP_NOMOVE | PositioningFlags.SWP_NOZORDER));
        }
        public static Size GetHwndSize(IntPtr hwnd)
        {
            var rect = new RECT();
            GetWindowRect(hwnd, out rect);
            var result = new Size(rect.Right - rect.Left, rect.Bottom - rect.Top);
            return result;
        }
        #endregion

        #region Hwnd Functions
        public static List<IntPtr> EnumChildren(IntPtr hwnd)
        {
            var child = IntPtr.Zero;
            var results = new List<IntPtr>();
            do
            {
                child = FindWindowEx(hwnd, child, null, null);
                if (child != IntPtr.Zero) results.Add(child);
            } while (child != IntPtr.Zero);
            return results;
        }
        public static IntPtr GetHwndChild(IntPtr hwnd, string clsName, string ctrlText)
        {
            return FindWindowEx(hwnd, IntPtr.Zero, clsName, ctrlText);
        }
        public static IntPtr GetHwndParent(IntPtr hwnd)
        {
            return GetParent(hwnd);
        }
        public static int SendMessage(IntPtr hwnd, WM msg, uint param1, uint param2)
        {
            return (int)SendMessage(hwnd, (uint) msg, param1, param2);
        }
        public static int SendMessage(IntPtr hwnd, WM msg, uint param1, string param2)
        {
            return (int)SendMessage(hwnd, (uint)msg, param1, param2);
        }
        public static string GetMessageString(IntPtr hwnd, WM msg, uint param)
        {
            var sb = new StringBuilder(65536);
            SendMessage(hwnd, (uint) msg, param, sb);
            return sb.ToString();
        }
        public static int GetMessageInt(IntPtr hwnd, WM msg)
        {
            return (int) SendMessage(hwnd, (uint) msg, 0, 0);
        }
        public static void ClickHwnd(IntPtr hwnd)
        {
            SendMessage(hwnd, (uint)WM.BN_CLICKED, IntPtr.Zero, IntPtr.Zero);

			//SendMessage(nChildHandle, 0x201, 0, 0); //Mouse left down
			//SendMessage(nChildHandle, 0x202, 0, 0); //Mouse left up
        }
        #endregion

        #region lib
        [DllImport("user32.dll")]
        private static extern int FindWindow(string lpClassName, string lpWindowName);

        // Standard interface
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);

        // Sending messages by string
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, uint wParam, string lParam);

        // Retrieving string data
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, uint wParam, StringBuilder lParam);

        // Retrieving numeric data
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, uint wParam, uint lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindowEx(IntPtr parentHandle, IntPtr childAfter, string className, string windowTitle);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("USER32.DLL")]
        private static extern bool SetWindowText(IntPtr hWnd, string lpString);

        [DllImport("user32.dll")]
        private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool CloseWindow(IntPtr hWnd);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Auto)]
        private static extern IntPtr GetParent(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);
        #endregion

    }
}
