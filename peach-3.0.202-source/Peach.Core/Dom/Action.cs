
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
using System.Text;
using System.Threading;
using System.Xml;
using NLog;

using Peach.Core;
using Peach.Core.Cracker;
using Peach.Core.Dom.XPath;
using System.Xml.Serialization;
using System.IO; 
using System.ComponentModel;
using System.Data;  
using System.IO.MemoryMappedFiles;  
using System.Runtime.InteropServices;  
using Peach.Core.Runtime; 
using Peach.Core.IO;


namespace Peach.Core.Dom
{
	/// <summary>
	/// Action types
	/// </summary>
	public enum ActionType
	{
		Unknown,

		Start,
		Stop,

		Accept,
		Connect,
		Open,
		Close,

		Input,
		Output,

		Call,
		SetProperty,
		GetProperty,

		ChangeState,
		Slurp
	}

	public delegate void ActionStartingEventHandler(Action action);
	public delegate void ActionFinishedEventHandler(Action action);

	/// <summary>
	/// Performs an Action such as sending output,
	/// calling a method, etc.
	/// </summary>
	[Serializable]
	public class Action : INamed
	{

		[DllImport(@"peachControl", EntryPoint="newPath")]   
        public static unsafe extern int newPath();   

        [DllImport(@"peachControl", EntryPoint="clear_trace_bits")]   
        public static unsafe extern void clear_trace_bits();  
  
		[DllImport(@"peachControl", EntryPoint="count_branch")]   
        public static unsafe extern int count_branch();   

		[DllImport(@"peachControl", EntryPoint="hash_after_classify")]   
        public static unsafe extern int hash_after_classify(); 

		[DllImport(@"peachControl", EntryPoint="termination_detection_init")]   
        public static unsafe extern void termination_detection_init(); 

		[DllImport(@"peachControl", EntryPoint="termination_detection")]   
        public static unsafe extern int termination_detection();
		static NLog.Logger logger = LogManager.GetCurrentClassLogger();
		static int nameNum = 0;
		public string _name = "Unknown Action " + (++nameNum);
		public ActionType type = ActionType.Unknown;

		public State parent = null;

		protected DataModel _dataModel;
		protected DataModel _origionalDataModel;
		protected DataSet _dataSet;

		protected List<ActionParameter> _params = new List<ActionParameter>();
		protected ActionResult _result = null;

		protected string _publisher = null;
		protected string _when = null;
		protected string _onStart = null;
		protected string _onComplete = null;
		protected string _ref = null;
		protected string _method = null;
		protected string _property = null;
		//protected string _value = null;
		protected string _setXpath = null;
		protected string _valueXpath = null;
		public static string GetTimeStamp()
        {
	Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;        
    //TimeSpan ts = DateTime.UtcNow;
//	    System.DateTime time = System.DateTime.Now;
	
  //          long ts = ConvertDateTimeToInt(time);
            return Convert.ToInt64(unixTimestamp).ToString();
        }
		public string name
		{
			get { return _name; }
			set { _name = value; }
		}

		/// <summary>
		/// Data attached to action
		/// </summary>
		public DataSet dataSet
		{
			get { return _dataSet; }
			set { _dataSet = value; }
		}

		/// <summary>
		/// Current copy of the data model we are mutating.
		/// </summary>
		public DataModel dataModel
		{
			get { return _dataModel; }
			set
			{
				//if (_origionalDataModel == null)
				//{
				//    // Optimize output by generateing value
				//    object tmp = value.Value;

				//    _origionalDataModel = ObjectCopier.Clone<DataModel>(value);
				//    _origionalDataModel.action = this;
				//    _origionalDataModel.dom = null;

				//    _dataModel = value;
				//    _dataModel.action = this;
				//    _dataModel.dom = null;
				//}
				//else
				//{
				_dataModel = value;
				if (_dataModel != null)
				{
					_dataModel.action = this;
					_dataModel.dom = null;
				}
				//}
			}
		}

		/// <summary>
		/// Origional copy of the data model we will be mutating.
		/// </summary>
		public DataModel origionalDataModel
		{
			get { return _origionalDataModel; }
			set
			{
				_origionalDataModel = value;

				// Optimize output by pre-generating value
				var tmp = _origionalDataModel.Value;
				System.Diagnostics.Debug.Assert(tmp != null);
			}
		}

		/// <summary>
		/// Action was started
		/// </summary>
		public bool started { get; set; }

		/// <summary>
		/// Action finished
		/// </summary>
		public bool finished { get; set; }

		/// <summary>
		/// Action errored
		/// </summary>
		public bool error { get; set; }

		//public string value
		//{
		//    get { return _value; }
		//    set { _value = value; }
		//}

		/// <summary>
		/// Array of parameters for a method call
		/// </summary>
		public List<ActionParameter> parameters
		{
			get { return _params; }
			set { _params = value; }
		}

		/// <summary>
		/// Action result for a method call
		/// </summary>
		public ActionResult result
		{
			get { return _result; }
			set { _result = value; }
		}

		/// <summary>
		/// xpath for selecting set targets during slurp.
		/// </summary>
		/// <remarks>
		/// Can return multiple elements.  All returned elements
		/// will be updated with a new value.
		/// </remarks>
		public string setXpath
		{
			get { return _setXpath; }
			set { _setXpath = value; }
		}

		/// <summary>
		/// xpath for selecting value during slurp
		/// </summary>
		/// <remarks>
		/// Must return a single element.
		/// </remarks>
		public string valueXpath
		{
			get { return _valueXpath; }
			set { _valueXpath = value; }
		}

		/// <summary>
		/// Name of publisher to use
		/// </summary>
		public string publisher
		{
			get { return _publisher; }
			set { _publisher = value; }
		}

		/// <summary>
		/// Only run action when expression is true
		/// </summary>
		public string when
		{
			get { return _when; }
			set { _when = value; }
		}

		/// <summary>
		/// Expression to run when action is starting
		/// </summary>
		public string onStart
		{
			get { return _onStart; }
			set { _onStart = value; }
		}

		/// <summary>
		/// Expression to run when action is completed
		/// </summary>
		public string onComplete
		{
			get { return _onComplete; }
			set { _onComplete = value; }
		}

		/// <summary>
		/// Name of state to change to, type=ChangeState
		/// </summary>
		public string reference
		{
			get { return _ref; }
			set { _ref = value; }
		}

		/// <summary>
		/// Method to call
		/// </summary>
		public string method
		{
			get { return _method; }
			set { _method = value; }
		}

		/// <summary>
		/// Property to operate on
		/// </summary>
		public string property
		{
			get { return _property; }
			set { _property = value; }
		}

		/// <summary>
		/// Returns true if this action requires a dataModel
		/// </summary>
		public bool dataModelRequired
		{
			get
			{
				switch (type)
				{
					case ActionType.Input:
					case ActionType.Output:
					case ActionType.GetProperty:
					case ActionType.SetProperty:
						return true;
					default:
						return false;
				}
			}
		}

		/// <summary>
		/// Action is starting to execute
		/// </summary>
		public static event ActionStartingEventHandler Starting;
		/// <summary>
		/// Action has finished executing
		/// </summary>
		public static event ActionFinishedEventHandler Finished;

		protected virtual void OnStarting()
		{
			if (!string.IsNullOrEmpty(onStart))
			{
				Dictionary<string, object> state = new Dictionary<string, object>();
				state["action"] = this;
				state["state"] = this.parent;
				state["self"] = this;

				Scripting.EvalExpression(onStart, state);
			}

			if (Starting != null)
				Starting(this);
		}

		protected virtual void OnFinished()
		{
			if (!string.IsNullOrEmpty(onComplete))
			{
				Dictionary<string, object> state = new Dictionary<string, object>();
				state["action"] = this;
				state["state"] = this.parent;
				state["self"] = this;

				Scripting.EvalExpression(onComplete, state);
			}

			if (Finished != null)
				Finished(this);
		}

		/// <summary>
		/// Update any DataModels we contain to new clones of
		/// origionalDataModel.
		/// </summary>
		/// <remarks>
		/// This should be performed in StateModel to every State/Action at
		/// start of the iteration.
		/// </remarks>
		public void UpdateToOrigionalDataModel()
		{
			switch (type)
			{
				case ActionType.Start:
				case ActionType.Stop:
				case ActionType.Open:
				case ActionType.Connect:
				case ActionType.Close:
				case ActionType.Accept:
				case ActionType.ChangeState:
				case ActionType.Slurp:
					break;

				case ActionType.Input:
				case ActionType.Output:
				case ActionType.GetProperty:
				case ActionType.SetProperty:
					logger.Debug("Updating action to original data model");
					dataModel = origionalDataModel.Clone() as DataModel;
					dataModel.action = this;

					break;

				case ActionType.Call:
					foreach (ActionParameter p in this.parameters)
					{
						logger.Debug("Updating action parameter to original data model");
						p.dataModel = p.origionalDataModel.Clone() as DataModel;
						p.dataModel.action = this;
					}

					if (result != null)
					{
						logger.Debug("Updating action result to original data model");
						result.dataModel = result.origionalDataModel.Clone() as DataModel;
						result.dataModel.action = this;
					}

					break;

				default:
					throw new ApplicationException("Error, Action.Run fell into unknown Action type handler!");
			}
		}

		public void Run(RunContext context)
		{
			logger.Trace("Run({0}): {1}", name, type);
			

			if (when != null)
			{
				Dictionary<string, object> state = new Dictionary<string, object>();
				state["context"] = context;
				state["Context"] = context;
				state["action"] = this;
				state["Action"] = this;
				state["state"] = this.parent;
				state["State"] = this.parent;
				state["StateModel"] = this.parent.parent;
				state["Test"] = this.parent.parent.parent;
				state["self"] = this;

				object value = Scripting.EvalExpression(when, state);
				if (!(value is bool))
				{
				        logger.Debug("Run: action '{0}' when return is not boolean, returned: {1}", name, value);
					return;
				}

				if (!(bool)value)
				{
				        logger.Debug("Run: action '{0}' when returned false", name);
					return;
				}
			}

			try
			{
				Publisher publisher = null;
				if (this.publisher != null && this.publisher != "Peach.Agent")
				{
					if (!context.test.publishers.ContainsKey(this.publisher))
					{
						logger.Debug("Run: Publisher '" + this.publisher + "' not found!");
						throw new PeachException("Error, Action '" + name + "' publisher value '" + this.publisher + "' was not found!");
					}

					publisher = context.test.publishers[this.publisher];
				}
				else
				{
					publisher = context.test.publishers[0];
				}

				if (context.controlIteration && context.controlRecordingIteration)
				{
					logger.Debug("Run: Adding action to controlRecordingActionsExecuted");
					context.controlRecordingActionsExecuted.Add(this);
				}
				else if (context.controlIteration)
				{
					logger.Debug("Run: Adding action to controlActionsExecuted");
					context.controlActionsExecuted.Add(this);
				}

				started = true;
				finished = false;
				error = false;

				OnStarting();

				//从发现第一条路径起开始算	
				if(Peach.Core.Runtime.SHARE.cur_path == 0){
					Peach.Core.Runtime.SHARE.last_path_time = DateTime.Now;
				}

unsafe{
				//只有当type是Output时才执行覆盖率相关信息
				if(type == ActionType.Output){
					clear_trace_bits();  
				}
} 
				logger.Debug("ActionType.{0}", type.ToString());

				switch (type)
				{
					case ActionType.Start:
						publisher.start();
						break;

					case ActionType.Stop:
						publisher.close();
						publisher.stop();
						break;

					case ActionType.Open:
					case ActionType.Connect:
						publisher.start();
						publisher.open();
						break;

					case ActionType.Close:
						publisher.start();
						publisher.close();
						break;

					case ActionType.Accept:
						publisher.start();
						publisher.open();
						publisher.accept();
						break;

					case ActionType.Input:
						publisher.start();
						publisher.open();
						publisher.input();
						handleInput(publisher);
						parent.parent.dataActions.Add(this);
						break;

					case ActionType.Output:
						publisher.start();
						publisher.open();
						handleOutput(publisher);
						parent.parent.dataActions.Add(this);
						break;

					case ActionType.Call:
						publisher.start();
						handleCall(publisher, context);
						parent.parent.dataActions.Add(this);
						break;

					case ActionType.GetProperty:
						publisher.start();
						handleGetProperty(publisher);
						parent.parent.dataActions.Add(this);
						break;

					case ActionType.SetProperty:
						publisher.start();
						handleSetProperty(publisher);
						parent.parent.dataActions.Add(this);
						break;

					case ActionType.ChangeState:
						handleChangeState();
						break;

					case ActionType.Slurp:
						handleSlurp(context);
						break;

					default:
						throw new ApplicationException("Error, Action.Run fell into unknown Action type handler!");
				}

				finished = true;
			}
			catch
			{
				error = true;
				finished = true;
				throw;
			}
			finally
			{ 
unsafe{
				//只有当action是output才执行内存相关动作
				if(type == ActionType.Output){
					Thread.Sleep(100);
					//判断待测程序是否执行完
					Console.WriteLine("Checking whether the program has completed its tasks ......");
					// int cur_cksum = hash_after_classify();
					// int last_cksum = cur_cksum + 1;
					int cnt = 0;
					termination_detection_init();
					while(termination_detection() != 0)
					{
						Thread.Sleep(10);
						// last_cksum = cur_cksum;
						// cur_cksum = hash_after_classify();
						cnt++;
						Console.WriteLine("Checking iteration {0} ...", cnt);
					}
					Console.WriteLine("Program has finished its tasks after {0} times of check......", cnt + 1);

					int hnb = newPath();
					if(hnb != 0)
					{
						//update path_info
						Console.WriteLine("feilong:LLVM find new path.");
						Peach.Core.Runtime.SHARE.has_new_path = true;
						Peach.Core.Runtime.SHARE.cur_path++; 
						if(hnb == 2)
							Peach.Core.Runtime.SHARE.has_new_path_branch = true;
						else 
							Peach.Core.Runtime.SHARE.has_new_path_branch = false;
						Peach.Core.Runtime.SHARE.has_new_path_iteration = true;
						string time = GetTimeStamp();
						string info =  Convert.ToString(Peach.Core.Runtime.SHARE.cur_path);
						// string[] names = new string[] {time, info};
						string sPath = Peach.Core.Runtime.SHARE.pathSrc; 
						if (!File.Exists(sPath))  
						{ 
							FileStream fs = new FileStream(sPath, FileMode.Create, FileAccess.Write); 
							StreamWriter sw = new StreamWriter(fs); 
							StringBuilder sb = new StringBuilder(); 
							sb.Append("Date").Append(",").Append("Amount"); 
							sw.WriteLine(sb); 
							sw.Flush();
							sw.Close();
							fs.Close();
						} 
						var csv = new StringBuilder(); 
						var newLine = string.Format("{0},{1}", time, info);
						csv.AppendLine(newLine);   
						File.AppendAllText(sPath, csv.ToString()); 
					}
					else{
						Console.WriteLine("feilong:LLVM find no new path.");
						Peach.Core.Runtime.SHARE.has_new_path = false;
					}
					//update branch_info
					int branch = count_branch();
					if (branch > Peach.Core.Engine.total_branch)
					{
						Console.WriteLine("New Branch hit!");
						Peach.Core.Engine.total_branch = branch;
						//  string bPath = Peach.Core.Runtime.SHARE.pathSrc; 
						string bPath = Peach.Core.Runtime.SHARE.pathSSrc; 	//"/tmp/peachBranch.csv";
						if (!File.Exists(bPath))  
						{ 
							FileStream fs = new FileStream(bPath, FileMode.Create, FileAccess.Write); 
							StreamWriter sw = new StreamWriter(fs); 
							StringBuilder sb = new StringBuilder(); 
							sb.Append("Date").Append(",").Append("Amount"); 
							sw.WriteLine(sb); 
							sw.Flush();
							sw.Close();
							fs.Close();
						} 
						var csv = new StringBuilder(); 
						string time = GetTimeStamp();
						string info =  Convert.ToString(Peach.Core.Engine.total_branch);
						var newLine = string.Format("{0},{1}", time, info);
						csv.AppendLine(newLine);   
						File.AppendAllText(bPath, csv.ToString());
					}
					else{
						Console.WriteLine("Opps!! No New Branch found!");
					}
				}
}
				//只有当action是output才执行进队列的操作 并且需要当前非repo的叠加模式 
				if(type == ActionType.Output && (!(Peach.Core.Runtime.SHARE.if_PeachStarRepo && (context.test.strategy.Iteration < Peach.Core.Runtime.SHARE.peachStarRepoStartIteration)))){
					//check if this DataMode
					if(Peach.Core.Runtime.SHARE.ifuse && Peach.Core.Runtime.SHARE.has_new_path){
						
						//计算间隔时间
						int time_bridge = (int) DateTime.Now.Subtract(Peach.Core.Runtime.SHARE.last_path_time).TotalMilliseconds;
						
						//计算新平均时间
						Peach.Core.Runtime.SHARE.average_path_time = 
							((Peach.Core.Runtime.SHARE.cur_path -1) * Peach.Core.Runtime.SHARE.average_path_time + time_bridge)/
							Peach.Core.Runtime.SHARE.cur_path;
						
						
						//计算概率
						this.dataModel.p = Math.Min(1, time_bridge * 1.0/Peach.Core.Runtime.SHARE.average_path_time);

						//更新上一条路径的时间
						Peach.Core.Runtime.SHARE.last_path_time = DateTime.Now;

						//进队列
						Peach.Core.Runtime.SHARE.dataModelsToMutate.Enqueue(this.dataModel.Clone() as DataModel);
						// Peach.Core.Runtime.SHARE.dataModelsToMutate.Enqueue(this.dataModel);

						//进种子池
						if(Peach.Core.Runtime.SHARE.has_new_path_branch)
						{
							Peach.Core.Runtime.SHARE.valuableDataModels.Enqueue(this.dataModel.Clone() as DataModel);
							Peach.Core.Runtime.SHARE.seedPoolIndexQueue.Enqueue(++Peach.Core.Runtime.SHARE.seedPoolIndex);

							Peach.Core.Runtime.SHARE.saveNewSeedToFile(this.dataModel.Clone() as DataModel,(Peach.Core.Loggers.FileLogger)context.test.loggers[0]);

						}

						Console.WriteLine("feilong: Find new path, add DataModel to queue. queue length before {0} queue length now {1} use time: {2}. average time {3} and the p is {4}  {5} ",
							Peach.Core.Runtime.SHARE.queueLengthBeforeIteration,Peach.Core.Runtime.SHARE.dataModelsToMutate.Count,
							time_bridge, Peach.Core.Runtime.SHARE.average_path_time, this.dataModel.p,
							Peach.Core.Runtime.SHARE.if_replace_just_now == true? "by replace" : ""
							);
					}
					//不管有没有新path都要置false
					Peach.Core.Runtime.SHARE.if_replace_just_now = false;
				}
				OnFinished(); 
			}
		}

		protected void handleInput(Publisher publisher)
		{
			try
			{
				DataCracker cracker = new DataCracker();
				cracker.CrackData(dataModel, new IO.BitStream(publisher));
			}
			catch (CrackingFailure ex)
			{
				throw new SoftException(ex);
			}
		}

		protected void handleOutput(Publisher publisher)
		{
			Stream strm = dataModel.Value.Stream;
			strm.Seek(0, SeekOrigin.Begin);

			MemoryStream ms = strm as MemoryStream;
			if (ms == null)
			{
				ms = new MemoryStream();
				strm.CopyTo(ms);
				ms.Seek(0, SeekOrigin.Begin);
				strm.Seek(0, SeekOrigin.Begin);
			}

			Console.WriteLine("feilong: Publisher output!!!");
			publisher.output(ms.GetBuffer(), (int)ms.Position, (int)ms.Length);
		}

		protected void handleCall(Publisher publisher, RunContext context)
		{
			Variant ret = null;

			// Are we sending to Agents?
			if (this.publisher == "Peach.Agent")
				ret = context.agentManager.Message("Action.Call", new Variant(this.method));
			else
				ret = publisher.call(method, parameters);

			if (result != null && ret != null)
			{
				BitStream data;

				try
				{
					data = (BitStream)ret;
				}
				catch (NotSupportedException)
				{
					throw new PeachException("Error, unable to convert result from method '" + this.method + "' to a BitStream");
				}

				try
				{
					DataCracker cracker = new DataCracker();
					cracker.CrackData(result.dataModel, data);
				}
				catch (CrackingFailure ex)
				{
					throw new SoftException(ex);
				}
			}
		}

		protected void handleGetProperty(Publisher publisher)
		{
			Variant result = publisher.getProperty(property);
			this.dataModel.DefaultValue = result;
		}

		protected void handleSetProperty(Publisher publisher)
		{
			publisher.setProperty(property, this.dataModel.InternalValue);
		}

		protected void handleChangeState()
		{
			if (!this.parent.parent.states.ContainsKey(reference))
			{
				logger.Debug("handleChangeState: Error, unable to locate state '" + reference + "'");
				throw new PeachException("Error, unable to locate state '" + reference + "' provided to action '" + name + "'");
			}

			logger.Debug("handleChangeState: Changing to state: " + reference);

			throw new ActionChangeStateException(this.parent.parent.states[reference]);
		}

		class PeachXmlNamespaceResolver : IXmlNamespaceResolver
		{
			public IDictionary<string, string> GetNamespacesInScope(XmlNamespaceScope scope)
			{
				return new Dictionary<string, string>();
			}

			public string LookupNamespace(string prefix)
			{
				return prefix;
			}

			public string LookupPrefix(string namespaceName)
			{
				return namespaceName;
			}
		}

		protected void handleSlurp(RunContext context)
		{
			PeachXmlNamespaceResolver resolver = new PeachXmlNamespaceResolver();
			PeachXPathNavigator navi = new PeachXPathNavigator(context.dom);
			var iter = navi.Select(valueXpath, resolver);
			if (!iter.MoveNext())
				throw new SoftException("Error, slurp valueXpath returned no values. [" + valueXpath + "]");

			DataElement valueElement = ((PeachXPathNavigator)iter.Current).currentNode as DataElement;
			if (valueElement == null)
				throw new SoftException("Error, slurp valueXpath did not return a Data Element. [" + valueXpath + "]");

			if (iter.MoveNext())
				throw new SoftException("Error, slurp valueXpath returned multiple values. [" + valueXpath + "]");

			iter = navi.Select(setXpath, resolver);

			if (!iter.MoveNext())
				throw new SoftException("Error, slurp setXpath returned no values. [" + setXpath + "]");

			do
			{
				var setElement = ((PeachXPathNavigator)iter.Current).currentNode as DataElement;
				if (setElement == null)
					throw new PeachException("Error, slurp setXpath did not return a Data Element. [" + valueXpath + "]");

				logger.Debug("Slurp, setting " + setElement.fullName + " from " + valueElement.fullName);
				setElement.DefaultValue = valueElement.DefaultValue;
			}
			while (iter.MoveNext());
		}
	}

	public enum ActionParameterType
	{
		In,
		Out,
		InOut
	}

	[Serializable]
	public class ActionParameter
	{
		static int nameNum = 0;

		string _name = "Unknown Parameter " + (++nameNum);
		ActionParameterType _type;

		[NonSerialized]
		DataModel _origionalDataModel = null;
		DataModel _dataModel = null;

		public object data;

		public string name
		{
			get { return _name; }
			set { _name = value; }
		}

		public ActionParameterType type
		{
			get { return _type; }
			set { _type = value; }
		}

		public DataModel origionalDataModel
		{
			get { return _origionalDataModel; }
			set { _origionalDataModel = value; }
		}

		public DataModel dataModel
		{
			get { return _dataModel; }
			set
			{
				_dataModel = value;

				if (_origionalDataModel == null)
					_origionalDataModel = _dataModel.Clone() as DataModel;
			}
		}
	}

	[Serializable]
	public class ActionResult
	{
		static int nameNum = 0;

		string _name = "Unknown Result " + (++nameNum);

		[NonSerialized]
		DataModel _origionalDataModel = null;
		DataModel _dataModel = null;

		public string name
		{
			get { return _name; }
			set { _name = value; }
		}

		public DataModel origionalDataModel
		{
			get { return _origionalDataModel; }
			set { _origionalDataModel = value; }
		}

		public DataModel dataModel
		{
			get { return _dataModel; }
			set
			{
				_dataModel = value;

				if (_origionalDataModel == null)
					_origionalDataModel = _dataModel.Clone() as DataModel;
			}
		}
	}

	[Serializable]
	public class ActionChangeStateException : Exception
	{
		public State changeToState;

		public ActionChangeStateException(State changeToState)
		{
			this.changeToState = changeToState;
		}
	}
}

// END
