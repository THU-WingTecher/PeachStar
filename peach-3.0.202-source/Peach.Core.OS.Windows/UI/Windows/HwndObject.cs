﻿using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using Point=System.Drawing.Point;

namespace Peach.Core.UI.Windows
{
    /// <summary>
    /// Allows the searching, navigation, and manipulation of Hwnd objects.
    /// </summary>
    public class HwndObject
    {
        /// <summary>
        /// The windows handle to this object.
        /// </summary>
        public IntPtr Hwnd { get; private set; }

        /// <summary>
        /// The registered class name (if any) of this object.
        /// </summary>
        public string ClassName
        {
            get { return HwndInterface.GetHwndClassName(Hwnd); }
        }

        /// <summary>
        /// The title of this object - Setting this will only effect window title-bar text.
        /// </summary>
        public string Title
        {
            get { return HwndInterface.GetHwndTitle(Hwnd); }
            set { HwndInterface.SetHwndTitle(Hwnd, value); }
        }

        /// <summary>
        /// The text of this item - setting this will only effect controls and only with appropriate access/privacy
        /// </summary>
        public string Text
        {
            get { return HwndInterface.GetHwndText(Hwnd); }
            set { HwndInterface.SetHwndText(Hwnd, value); }
        }

        /// <summary>
        /// The location of this Hwnd Object.
        /// </summary>
        public Point Location
        {
            get { return HwndInterface.GetHwndPos(Hwnd); }
            set { HwndInterface.SetHwndPos(Hwnd, (int)value.X, (int)value.Y); }
        }

        /// <summary>
        /// The size of this Hwnd Object.
        /// </summary>
        public Size Size
        {
            get { return HwndInterface.GetHwndSize(Hwnd); }
            set { HwndInterface.SetHwndSize(Hwnd, (int)value.Width, (int)value.Height); }
        }

        /// <summary>
        /// Retrieves all top-level Hwnd Objects.
        /// </summary>
        /// <returns></returns>
        public static List<HwndObject> GetWindows()
        {
            var result = new List<HwndObject>();
            foreach (var hwnd in HwndInterface.EnumHwnds())
                result.Add(new HwndObject(hwnd));
            return result;
        }

        /// <summary>
        /// Gets the first top-level HwndObject with the given title.
        /// </summary>
        /// <param name="title"></param>
        /// <returns></returns>
        public static HwndObject GetWindowByTitle(string title)
        {
            return new HwndObject(HwndInterface.GetHwndFromTitle(title));
        }

        /// <summary>
        /// Initialized a new HwndObject.
        /// </summary>
        /// <param name="hwnd"></param>
        public HwndObject(IntPtr hwnd)
        {
            Hwnd = hwnd;
        }

        /// <summary>
        /// Sends a message to this Hwnd Object
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="param1"></param>
        /// <param name="param2"></param>
        public void SendMessage(WM msg, uint param1, string param2)
        {
            HwndInterface.SendMessage(Hwnd, msg, param1, param2);
        }
        /// <summary>
        /// Sends a message to this Hwnd Object
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="param1"></param>
        /// <param name="param2"></param>
        public void SendMessage(WM msg, uint param1, uint param2)
        {
            HwndInterface.SendMessage(Hwnd, msg, param1, param2);
        }
        /// <summary>
        /// Returns a string result from a message.
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="param"></param>
        /// <returns></returns>
        public string GetMessageString(WM msg, uint param)
        {
            return HwndInterface.GetMessageString(Hwnd, msg, param);
        }
        /// <summary>
        /// Returns an integer result from a message.
        /// </summary>
        /// <param name="msg"></param>
        /// <returns></returns>
        public int GetMessageInt(WM msg)
        {
            return HwndInterface.GetMessageInt(Hwnd, msg);
        }

        /// <summary>
        /// Simulates a user-click on this object.
        /// </summary>
        public void Click()
        {
            HwndInterface.ClickHwnd(Hwnd);
        }

		/// <summary>
		/// Send a WM_CLOSE message to window
		/// </summary>
		public void Close()
		{
			SendMessage(WM.CLOSE, 0, 0);
		}

        /// <summary>
        /// Seeks a parent for this Hwnd Object (if any).
        /// </summary>
        /// <returns></returns>
        public HwndObject GetParent()
        {
            return new HwndObject(HwndInterface.GetHwndParent(Hwnd));
        }

        /// <summary>
        /// Seeks all children of this Hwnd Object.
        /// </summary>
        /// <returns></returns>
        public List<HwndObject> GetChildren()
        {
            var result = new List<HwndObject>();
            foreach (var hwnd in HwndInterface.EnumChildren(Hwnd))
                result.Add(new HwndObject(hwnd));
            return result;
        }

        /// <summary>
        /// Retrieves a child Hwnd Object by its class and title.
        /// </summary>
        /// <param name="cls"></param>
        /// <param name="title"></param>
        /// <returns></returns>
        public HwndObject GetChild(string cls, string title)
        {
            var hwnd = HwndInterface.GetHwndChild(Hwnd, cls, title);
            return new HwndObject(hwnd);
        }

        public override string ToString()
        {
            var pt = Location;
            var sz = Size;
            var result =
                string.Format(
                    "({0}) {1},{2}:{3}x{4} \"{5}\"",
                    Hwnd,
                    pt.X, pt.Y,
                    sz.Width, sz.Height,
                    Title);
            return result;
        }

        #region Operators
        public static bool operator ==(HwndObject a, HwndObject b)
        {
            return (a.Hwnd == b.Hwnd);
        }

        public static bool operator !=(HwndObject a, HwndObject b)
        {
            return !(a == b);
        }

        public bool Equals(HwndObject obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.Hwnd.Equals(Hwnd);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != typeof(HwndObject)) return false;
            return Equals((HwndObject)obj);
        }

        public override int GetHashCode()
        {
            return Hwnd.GetHashCode();
        }
        #endregion
    }
}
