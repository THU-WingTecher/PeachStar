using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Peach.Core.Dom;

namespace Peach.Core.Agent.Monitors
{
	[Monitor("Vmware", true)]
	[Parameter("Vmx", typeof(string), "Path to virtual machine")]
	[Parameter("Host", typeof(string), "Name of host machine", "")]
	[Parameter("Login", typeof(string), "Username for authentication on the remote machine", "")]
	[Parameter("Password", typeof(string), "Password for authentication on the remote machine", "")]
	[Parameter("HostType", typeof(Provider), "Type of remote host", "Default")]
	[Parameter("HostPort", typeof(int), "TCP/IP port on the remote host", "0")]
	[Parameter("SnapshotIndex", typeof(int?), "VM snapshot index", "")]
	[Parameter("SnapshotName", typeof(string), "VM snapshot name", "")]
	[Parameter("ResetEveryIteration", typeof(bool), "Reset VM on every iteration", "false")]
	[Parameter("ResetOnFaultBeforeCollection", typeof(bool), "Reset VM after we detect a fault during data collection", "false")]
	[Parameter("WaitForToolsInGuest", typeof(bool), "Wait for tools to start in guest", "true")]
	[Parameter("WaitTimeout", typeof(int), "How many seconds to wait for guest tools", "600")]
	public class VmwareMonitor : Monitor
	{
		static NLog.Logger logger = LogManager.GetCurrentClassLogger();

		public enum Provider
		{
			// Default
			Default = VixServiceProvider.VIX_SERVICEPROVIDER_DEFAULT,
			// vCenter Server, ESX/ESXi hosts, VMWare Server 2.0
			VIServer = VixServiceProvider.VIX_SERVICEPROVIDER_VMWARE_VI_SERVER,
			// VMWare Workstation
			Workstation = VixServiceProvider.VIX_SERVICEPROVIDER_VMWARE_WORKSTATION,
			// VMWare Workstation (Shared Mode)
			WorkstationShared = VixServiceProvider.VIX_SERVICEPROVIDER_VMWARE_WORKSTATION_SHARED,
			// VMWare Player
			Player = VixServiceProvider.VIX_SERVICEPROVIDER_VMWARE_PLAYER,
			// VMWare Server 1.0.x
			Server = VixServiceProvider.VIX_SERVICEPROVIDER_VMWARE_SERVER,
		}

		#region P/Invokes

		const string VixDll = "VixAllProducts.dll";
		const int VixApiVersion = -1;
		static readonly IntPtr VixInvalidHandle = IntPtr.Zero;

		delegate void VixEventProc(IntPtr handle,
			VixEventType eventType,
			IntPtr moreEventInfo,
			IntPtr clientData);

		enum VixEventType : int
		{
			VIX_EVENTTYPE_JOB_COMPLETED = 2,
			VIX_EVENTTYPE_JOB_PROGRESS  = 3,
			VIX_EVENTTYPE_FIND_ITEM     = 8,
		}

		enum VixServiceProvider : int
		{
			VIX_SERVICEPROVIDER_DEFAULT                   = 1,
			VIX_SERVICEPROVIDER_VMWARE_SERVER             = 2,
			VIX_SERVICEPROVIDER_VMWARE_WORKSTATION        = 3,
			VIX_SERVICEPROVIDER_VMWARE_PLAYER             = 4,
			VIX_SERVICEPROVIDER_VMWARE_VI_SERVER          = 10,
			VIX_SERVICEPROVIDER_VMWARE_WORKSTATION_SHARED = 11,
		}

		enum VixHostOptions : int
		{
			VIX_HOSTOPTION_NONE            = 0x0000,
		//	VIX_HOSTOPTION_USE_EVENT_PUMP  = 0x0008, Removed in version 1.11
			VIX_HOSTOPTION_VERIFY_SSL_CERT = 0x4000,
		}

		enum VixVMOpenOptions : int
		{
			VIX_VMOPEN_NORMAL = 0,
		}

		enum VixPropertyType : int
		{
			VIX_PROPERTYTYPE_ANY     = 0,
			VIX_PROPERTYTYPE_INTEGER = 1,
			VIX_PROPERTYTYPE_STRING  = 2,
			VIX_PROPERTYTYPE_BOOL    = 3,
			VIX_PROPERTYTYPE_HANDLE  = 4,
			VIX_PROPERTYTYPE_INT64   = 5,
			VIX_PROPERTYTYPE_BLOB    = 6
		}

		enum VixHandleType : int
		{
			VIX_HANDLETYPE_NONE               = 0,
			VIX_HANDLETYPE_HOST               = 2,
			VIX_HANDLETYPE_VM                 = 3,
			VIX_HANDLETYPE_NETWORK            = 5,
			VIX_HANDLETYPE_JOB                = 6,
			VIX_HANDLETYPE_SNAPSHOT           = 7,
			VIX_HANDLETYPE_PROPERTY_LIST      = 9,
			VIX_HANDLETYPE_METADATA_CONTAINER = 11
		}

		enum VixPropertyID : int
		{
			VIX_PROPERTY_NONE                                  = 0,

			// Properties used by several handle types.
			VIX_PROPERTY_META_DATA_CONTAINER                   = 2,

			// VIX_HANDLETYPE_HOST properties
			VIX_PROPERTY_HOST_HOSTTYPE                         = 50,
			VIX_PROPERTY_HOST_API_VERSION                      = 51,

			// VIX_HANDLETYPE_VM properties
			VIX_PROPERTY_VM_NUM_VCPUS                          = 101,
			VIX_PROPERTY_VM_VMX_PATHNAME                       = 103, 
			VIX_PROPERTY_VM_VMTEAM_PATHNAME                    = 105, 
			VIX_PROPERTY_VM_MEMORY_SIZE                        = 106,
			VIX_PROPERTY_VM_READ_ONLY                          = 107,
			VIX_PROPERTY_VM_NAME                               = 108,
			VIX_PROPERTY_VM_GUESTOS                            = 109,
			VIX_PROPERTY_VM_IN_VMTEAM                          = 128,
			VIX_PROPERTY_VM_POWER_STATE                        = 129,
			VIX_PROPERTY_VM_TOOLS_STATE                        = 152,
			VIX_PROPERTY_VM_IS_RUNNING                         = 196,
			VIX_PROPERTY_VM_SUPPORTED_FEATURES                 = 197,
		//	VIX_PROPERTY_VM_IS_RECORDING                       = 236, Removed in version 1.11
		//	VIX_PROPERTY_VM_IS_REPLAYING                       = 237, Removed in version 1.11
			VIX_PROPERTY_VM_SSL_ERROR                          = 293,

			// Result properties; these are returned by various procedures
			VIX_PROPERTY_JOB_RESULT_ERROR_CODE                 = 3000,
			VIX_PROPERTY_JOB_RESULT_VM_IN_GROUP                = 3001,
			VIX_PROPERTY_JOB_RESULT_USER_MESSAGE               = 3002,
			VIX_PROPERTY_JOB_RESULT_EXIT_CODE                  = 3004,
			VIX_PROPERTY_JOB_RESULT_COMMAND_OUTPUT             = 3005,
			VIX_PROPERTY_JOB_RESULT_HANDLE                     = 3010,
			VIX_PROPERTY_JOB_RESULT_GUEST_OBJECT_EXISTS        = 3011,
			VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_ELAPSED_TIME = 3017,
			VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_EXIT_CODE    = 3018,
			VIX_PROPERTY_JOB_RESULT_ITEM_NAME                  = 3035,
			VIX_PROPERTY_JOB_RESULT_FOUND_ITEM_DESCRIPTION     = 3036,
			VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_COUNT        = 3046,
			VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_HOST         = 3048,
			VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_FLAGS        = 3049,
			VIX_PROPERTY_JOB_RESULT_PROCESS_ID                 = 3051,
			VIX_PROPERTY_JOB_RESULT_PROCESS_OWNER              = 3052,
			VIX_PROPERTY_JOB_RESULT_PROCESS_COMMAND            = 3053,
			VIX_PROPERTY_JOB_RESULT_FILE_FLAGS                 = 3054,
			VIX_PROPERTY_JOB_RESULT_PROCESS_START_TIME         = 3055,
			VIX_PROPERTY_JOB_RESULT_VM_VARIABLE_STRING         = 3056,
			VIX_PROPERTY_JOB_RESULT_PROCESS_BEING_DEBUGGED     = 3057,
			VIX_PROPERTY_JOB_RESULT_SCREEN_IMAGE_SIZE          = 3058,
			VIX_PROPERTY_JOB_RESULT_SCREEN_IMAGE_DATA          = 3059,
			VIX_PROPERTY_JOB_RESULT_FILE_SIZE                  = 3061,
			VIX_PROPERTY_JOB_RESULT_FILE_MOD_TIME              = 3062,
			VIX_PROPERTY_JOB_RESULT_EXTRA_ERROR_INFO           = 3084,

			// Event properties; these are sent in the moreEventInfo for some events.
			VIX_PROPERTY_FOUND_ITEM_LOCATION                   = 4010,

			// VIX_HANDLETYPE_SNAPSHOT properties
			VIX_PROPERTY_SNAPSHOT_DISPLAYNAME                  = 4200,   
			VIX_PROPERTY_SNAPSHOT_DESCRIPTION                  = 4201,
			VIX_PROPERTY_SNAPSHOT_POWERSTATE                   = 4205,
		//	VIX_PROPERTY_SNAPSHOT_IS_REPLAYABLE                = 4207, Removed in version 1.11

			VIX_PROPERTY_GUEST_SHAREDFOLDERS_SHARES_PATH       = 4525,

			// Virtual machine encryption properties
			VIX_PROPERTY_VM_ENCRYPTION_PASSWORD                = 7001,
		}

		enum VixError : ulong
		{
			VIX_OK                                       = 0,

			// General errors
			VIX_E_FAIL                                   = 1,
			VIX_E_OUT_OF_MEMORY                          = 2,
			VIX_E_INVALID_ARG                            = 3,
			VIX_E_FILE_NOT_FOUND                         = 4,
			VIX_E_OBJECT_IS_BUSY                         = 5,
			VIX_E_NOT_SUPPORTED                          = 6,
			VIX_E_FILE_ERROR                             = 7,
			VIX_E_DISK_FULL                              = 8,
			VIX_E_INCORRECT_FILE_TYPE                    = 9,
			VIX_E_CANCELLED                              = 10,
			VIX_E_FILE_READ_ONLY                         = 11,
			VIX_E_FILE_ALREADY_EXISTS                    = 12,
			VIX_E_FILE_ACCESS_ERROR                      = 13,
			VIX_E_REQUIRES_LARGE_FILES                   = 14,
			VIX_E_FILE_ALREADY_LOCKED                    = 15,
			VIX_E_VMDB                                   = 16,
			VIX_E_NOT_SUPPORTED_ON_REMOTE_OBJECT         = 20,
			VIX_E_FILE_TOO_BIG                           = 21,
			VIX_E_FILE_NAME_INVALID                      = 22,
			VIX_E_ALREADY_EXISTS                         = 23,
			VIX_E_BUFFER_TOOSMALL                        = 24,
			VIX_E_OBJECT_NOT_FOUND                       = 25,
			VIX_E_HOST_NOT_CONNECTED                     = 26,
			VIX_E_INVALID_UTF8_STRING                    = 27,
			VIX_E_OPERATION_ALREADY_IN_PROGRESS          = 31,
			VIX_E_UNFINISHED_JOB                         = 29,
			VIX_E_NEED_KEY                               = 30,
			VIX_E_LICENSE                                = 32,
			VIX_E_VM_HOST_DISCONNECTED                   = 34,
			VIX_E_AUTHENTICATION_FAIL                    = 35,
			VIX_E_HOST_CONNECTION_LOST                   = 36,
			VIX_E_DUPLICATE_NAME                         = 41,

			// Handle Errors
			VIX_E_INVALID_HANDLE                         = 1000,
			VIX_E_NOT_SUPPORTED_ON_HANDLE_TYPE           = 1001,
			VIX_E_TOO_MANY_HANDLES                       = 1002,

			// XML errors
			VIX_E_NOT_FOUND                              = 2000,
			VIX_E_TYPE_MISMATCH                          = 2001,
			VIX_E_INVALID_XML                            = 2002,

			// VM Control Errors
			VIX_E_TIMEOUT_WAITING_FOR_TOOLS              = 3000,
			VIX_E_UNRECOGNIZED_COMMAND                   = 3001,
			VIX_E_OP_NOT_SUPPORTED_ON_GUEST              = 3003,
			VIX_E_PROGRAM_NOT_STARTED                    = 3004,
			VIX_E_CANNOT_START_READ_ONLY_VM              = 3005,
			VIX_E_VM_NOT_RUNNING                         = 3006,
			VIX_E_VM_IS_RUNNING                          = 3007,
			VIX_E_CANNOT_CONNECT_TO_VM                   = 3008,
			VIX_E_POWEROP_SCRIPTS_NOT_AVAILABLE          = 3009,
			VIX_E_NO_GUEST_OS_INSTALLED                  = 3010,
			VIX_E_VM_INSUFFICIENT_HOST_MEMORY            = 3011,
			VIX_E_SUSPEND_ERROR                          = 3012,
			VIX_E_VM_NOT_ENOUGH_CPUS                     = 3013,
			VIX_E_HOST_USER_PERMISSIONS                  = 3014,
			VIX_E_GUEST_USER_PERMISSIONS                 = 3015,
			VIX_E_TOOLS_NOT_RUNNING                      = 3016,
			VIX_E_GUEST_OPERATIONS_PROHIBITED            = 3017,
			VIX_E_ANON_GUEST_OPERATIONS_PROHIBITED       = 3018,
			VIX_E_ROOT_GUEST_OPERATIONS_PROHIBITED       = 3019,
			VIX_E_MISSING_ANON_GUEST_ACCOUNT             = 3023,
			VIX_E_CANNOT_AUTHENTICATE_WITH_GUEST         = 3024,
			VIX_E_UNRECOGNIZED_COMMAND_IN_GUEST          = 3025,
			VIX_E_CONSOLE_GUEST_OPERATIONS_PROHIBITED    = 3026,
			VIX_E_MUST_BE_CONSOLE_USER                   = 3027,
			VIX_E_VMX_MSG_DIALOG_AND_NO_UI               = 3028,
		//	VIX_E_NOT_ALLOWED_DURING_VM_RECORDING        = 3029, Removed in version 1.11
		//	VIX_E_NOT_ALLOWED_DURING_VM_REPLAY           = 3030, Removed in version 1.11
			VIX_E_OPERATION_NOT_ALLOWED_FOR_LOGIN_TYPE   = 3031,
			VIX_E_LOGIN_TYPE_NOT_SUPPORTED               = 3032,
			VIX_E_EMPTY_PASSWORD_NOT_ALLOWED_IN_GUEST    = 3033,
			VIX_E_INTERACTIVE_SESSION_NOT_PRESENT        = 3034,
			VIX_E_INTERACTIVE_SESSION_USER_MISMATCH      = 3035,
		//	VIX_E_UNABLE_TO_REPLAY_VM                    = 3039, Removed in version 1.11
			VIX_E_CANNOT_POWER_ON_VM                     = 3041,
			VIX_E_NO_DISPLAY_SERVER                      = 3043,
		//	VIX_E_VM_NOT_RECORDING                       = 3044, Removed in version 1.11
		//	VIX_E_VM_NOT_REPLAYING                       = 3045, Removed in version 1.11
			VIX_E_TOO_MANY_LOGONS                        = 3046,
			VIX_E_INVALID_AUTHENTICATION_SESSION         = 3047,

			// VM Errors
			VIX_E_VM_NOT_FOUND                           = 4000,
			VIX_E_NOT_SUPPORTED_FOR_VM_VERSION           = 4001,
			VIX_E_CANNOT_READ_VM_CONFIG                  = 4002,
			VIX_E_TEMPLATE_VM                            = 4003,
			VIX_E_VM_ALREADY_LOADED                      = 4004,
			VIX_E_VM_ALREADY_UP_TO_DATE                  = 4006,
			VIX_E_VM_UNSUPPORTED_GUEST                   = 4011,

			// Property Errors
			VIX_E_UNRECOGNIZED_PROPERTY                  = 6000,
			VIX_E_INVALID_PROPERTY_VALUE                 = 6001,
			VIX_E_READ_ONLY_PROPERTY                     = 6002,
			VIX_E_MISSING_REQUIRED_PROPERTY              = 6003,
			VIX_E_INVALID_SERIALIZED_DATA                = 6004,
			VIX_E_PROPERTY_TYPE_MISMATCH                 = 6005,

			// Completion Errors
			VIX_E_BAD_VM_INDEX                           = 8000,

			// Message errors
			VIX_E_INVALID_MESSAGE_HEADER                 = 10000,
			VIX_E_INVALID_MESSAGE_BODY                   = 10001,

			// Snapshot errors
			VIX_E_SNAPSHOT_INVAL                         = 13000,
			VIX_E_SNAPSHOT_DUMPER                        = 13001,
			VIX_E_SNAPSHOT_DISKLIB                       = 13002,
			VIX_E_SNAPSHOT_NOTFOUND                      = 13003,
			VIX_E_SNAPSHOT_EXISTS                        = 13004,
			VIX_E_SNAPSHOT_VERSION                       = 13005,
			VIX_E_SNAPSHOT_NOPERM                        = 13006,
			VIX_E_SNAPSHOT_CONFIG                        = 13007,
			VIX_E_SNAPSHOT_NOCHANGE                      = 13008,
			VIX_E_SNAPSHOT_CHECKPOINT                    = 13009,
			VIX_E_SNAPSHOT_LOCKED                        = 13010,
			VIX_E_SNAPSHOT_INCONSISTENT                  = 13011,
			VIX_E_SNAPSHOT_NAMETOOLONG                   = 13012,
			VIX_E_SNAPSHOT_VIXFILE                       = 13013,
			VIX_E_SNAPSHOT_DISKLOCKED                    = 13014,
			VIX_E_SNAPSHOT_DUPLICATEDDISK                = 13015,
			VIX_E_SNAPSHOT_INDEPENDENTDISK               = 13016,
			VIX_E_SNAPSHOT_NONUNIQUE_NAME                = 13017,
			VIX_E_SNAPSHOT_MEMORY_ON_INDEPENDENT_DISK    = 13018,
			VIX_E_SNAPSHOT_MAXSNAPSHOTS                  = 13019,
			VIX_E_SNAPSHOT_MIN_FREE_SPACE                = 13020,
			VIX_E_SNAPSHOT_HIERARCHY_TOODEEP             = 13021,
			VIX_E_SNAPSHOT_RRSUSPEND                     = 13022,
			VIX_E_SNAPSHOT_NOT_REVERTABLE                = 13024,

			// Host Errors
			VIX_E_HOST_DISK_INVALID_VALUE                = 14003,
			VIX_E_HOST_DISK_SECTORSIZE                   = 14004,
			VIX_E_HOST_FILE_ERROR_EOF                    = 14005,
			VIX_E_HOST_NETBLKDEV_HANDSHAKE               = 14006,
			VIX_E_HOST_SOCKET_CREATION_ERROR             = 14007,
			VIX_E_HOST_SERVER_NOT_FOUND                  = 14008,
			VIX_E_HOST_NETWORK_CONN_REFUSED              = 14009,
			VIX_E_HOST_TCP_SOCKET_ERROR                  = 14010,
			VIX_E_HOST_TCP_CONN_LOST                     = 14011,
			VIX_E_HOST_NBD_HASHFILE_VOLUME               = 14012,
			VIX_E_HOST_NBD_HASHFILE_INIT                 = 14013,
   
			// Disklib errors
			VIX_E_DISK_INVAL                             = 16000,
			VIX_E_DISK_NOINIT                            = 16001,
			VIX_E_DISK_NOIO                              = 16002,
			VIX_E_DISK_PARTIALCHAIN                      = 16003,
			VIX_E_DISK_NEEDSREPAIR                       = 16006,
			VIX_E_DISK_OUTOFRANGE                        = 16007,
			VIX_E_DISK_CID_MISMATCH                      = 16008,
			VIX_E_DISK_CANTSHRINK                        = 16009,
			VIX_E_DISK_PARTMISMATCH                      = 16010,
			VIX_E_DISK_UNSUPPORTEDDISKVERSION            = 16011,
			VIX_E_DISK_OPENPARENT                        = 16012,
			VIX_E_DISK_NOTSUPPORTED                      = 16013,
			VIX_E_DISK_NEEDKEY                           = 16014,
			VIX_E_DISK_NOKEYOVERRIDE                     = 16015,
			VIX_E_DISK_NOTENCRYPTED                      = 16016,
			VIX_E_DISK_NOKEY                             = 16017,
			VIX_E_DISK_INVALIDPARTITIONTABLE             = 16018,
			VIX_E_DISK_NOTNORMAL                         = 16019,
			VIX_E_DISK_NOTENCDESC                        = 16020,
			VIX_E_DISK_NEEDVMFS                          = 16022,
			VIX_E_DISK_RAWTOOBIG                         = 16024,
			VIX_E_DISK_TOOMANYOPENFILES                  = 16027,
			VIX_E_DISK_TOOMANYREDO                       = 16028,
			VIX_E_DISK_RAWTOOSMALL                       = 16029,
			VIX_E_DISK_INVALIDCHAIN                      = 16030,
			VIX_E_DISK_KEY_NOTFOUND                      = 16052, // metadata key is not found
			VIX_E_DISK_SUBSYSTEM_INIT_FAIL               = 16053,
			VIX_E_DISK_INVALID_CONNECTION                = 16054,
			VIX_E_DISK_ENCODING                          = 16061,
			VIX_E_DISK_CANTREPAIR                        = 16062,
			VIX_E_DISK_INVALIDDISK                       = 16063,
			VIX_E_DISK_NOLICENSE                         = 16064,
			VIX_E_DISK_NODEVICE                          = 16065,
			VIX_E_DISK_UNSUPPORTEDDEVICE                 = 16066,
			VIX_E_DISK_CAPACITY_MISMATCH                 = 16067,
			VIX_E_DISK_PARENT_NOTALLOWED                 = 16068,
			VIX_E_DISK_ATTACH_ROOTLINK                   = 16069,

			// Crypto Library Errors
			VIX_E_CRYPTO_UNKNOWN_ALGORITHM               = 17000,
			VIX_E_CRYPTO_BAD_BUFFER_SIZE                 = 17001,
			VIX_E_CRYPTO_INVALID_OPERATION               = 17002,
			VIX_E_CRYPTO_RANDOM_DEVICE                   = 17003,
			VIX_E_CRYPTO_NEED_PASSWORD                   = 17004,
			VIX_E_CRYPTO_BAD_PASSWORD                    = 17005,
			VIX_E_CRYPTO_NOT_IN_DICTIONARY               = 17006,
			VIX_E_CRYPTO_NO_CRYPTO                       = 17007,
			VIX_E_CRYPTO_ERROR                           = 17008,
			VIX_E_CRYPTO_BAD_FORMAT                      = 17009,
			VIX_E_CRYPTO_LOCKED                          = 17010,
			VIX_E_CRYPTO_EMPTY                           = 17011,
			VIX_E_CRYPTO_KEYSAFE_LOCATOR                 = 17012,

			// Remoting Errors.
			VIX_E_CANNOT_CONNECT_TO_HOST                 = 18000,
			VIX_E_NOT_FOR_REMOTE_HOST                    = 18001,
			VIX_E_INVALID_HOSTNAME_SPECIFICATION         = 18002,

			// Screen Capture Errors.
			VIX_E_SCREEN_CAPTURE_ERROR                   = 19000,
			VIX_E_SCREEN_CAPTURE_BAD_FORMAT              = 19001,
			VIX_E_SCREEN_CAPTURE_COMPRESSION_FAIL        = 19002,
			VIX_E_SCREEN_CAPTURE_LARGE_DATA              = 19003,

			// Guest Errors
			VIX_E_GUEST_VOLUMES_NOT_FROZEN               = 20000,
			VIX_E_NOT_A_FILE                             = 20001,
			VIX_E_NOT_A_DIRECTORY                        = 20002,
			VIX_E_NO_SUCH_PROCESS                        = 20003,
			VIX_E_FILE_NAME_TOO_LONG                     = 20004,
			VIX_E_OPERATION_DISABLED                     = 20005,

			// Tools install errors
			VIX_E_TOOLS_INSTALL_NO_IMAGE                 = 21000,
			VIX_E_TOOLS_INSTALL_IMAGE_INACCESIBLE        = 21001,
			VIX_E_TOOLS_INSTALL_NO_DEVICE                = 21002,
			VIX_E_TOOLS_INSTALL_DEVICE_NOT_CONNECTED     = 21003,
			VIX_E_TOOLS_INSTALL_CANCELLED                = 21004,
			VIX_E_TOOLS_INSTALL_INIT_FAILED              = 21005,
			VIX_E_TOOLS_INSTALL_AUTO_NOT_SUPPORTED       = 21006,
			VIX_E_TOOLS_INSTALL_GUEST_NOT_READY          = 21007,
			VIX_E_TOOLS_INSTALL_SIG_CHECK_FAILED         = 21008,
			VIX_E_TOOLS_INSTALL_ERROR                    = 21009,
			VIX_E_TOOLS_INSTALL_ALREADY_UP_TO_DATE       = 21010,
			VIX_E_TOOLS_INSTALL_IN_PROGRESS              = 21011,
			VIX_E_TOOLS_INSTALL_IMAGE_COPY_FAILED        = 21012,

			// Wrapper Errors
			VIX_E_WRAPPER_WORKSTATION_NOT_INSTALLED      = 22001,
			VIX_E_WRAPPER_VERSION_NOT_FOUND              = 22002,
			VIX_E_WRAPPER_SERVICEPROVIDER_NOT_FOUND      = 22003,
			VIX_E_WRAPPER_PLAYER_NOT_INSTALLED           = 22004,
			VIX_E_WRAPPER_RUNTIME_NOT_INSTALLED          = 22005,
			VIX_E_WRAPPER_MULTIPLE_SERVICEPROVIDERS      = 22006,

			// FuseMnt errors
			VIX_E_MNTAPI_MOUNTPT_NOT_FOUND               = 24000,
			VIX_E_MNTAPI_MOUNTPT_IN_USE                  = 24001,
			VIX_E_MNTAPI_DISK_NOT_FOUND                  = 24002,
			VIX_E_MNTAPI_DISK_NOT_MOUNTED                = 24003,
			VIX_E_MNTAPI_DISK_IS_MOUNTED                 = 24004,
			VIX_E_MNTAPI_DISK_NOT_SAFE                   = 24005,
			VIX_E_MNTAPI_DISK_CANT_OPEN                  = 24006,
			VIX_E_MNTAPI_CANT_READ_PARTS                 = 24007,
			VIX_E_MNTAPI_UMOUNT_APP_NOT_FOUND            = 24008,
			VIX_E_MNTAPI_UMOUNT                          = 24009,
			VIX_E_MNTAPI_NO_MOUNTABLE_PARTITONS          = 24010,
			VIX_E_MNTAPI_PARTITION_RANGE                 = 24011,
			VIX_E_MNTAPI_PERM                            = 24012,
			VIX_E_MNTAPI_DICT                            = 24013,
			VIX_E_MNTAPI_DICT_LOCKED                     = 24014,
			VIX_E_MNTAPI_OPEN_HANDLES                    = 24015,
			VIX_E_MNTAPI_CANT_MAKE_VAR_DIR               = 24016,
			VIX_E_MNTAPI_NO_ROOT                         = 24017,
			VIX_E_MNTAPI_LOOP_FAILED                     = 24018,
			VIX_E_MNTAPI_DAEMON                          = 24019,
			VIX_E_MNTAPI_INTERNAL                        = 24020,
			VIX_E_MNTAPI_SYSTEM                          = 24021,
			VIX_E_MNTAPI_NO_CONNECTION_DETAILS           = 24022,

			// VixMntapi errors
			VIX_E_MNTAPI_INCOMPATIBLE_VERSION            = 24300,
			VIX_E_MNTAPI_OS_ERROR                        = 24301,
			VIX_E_MNTAPI_DRIVE_LETTER_IN_USE             = 24302,
			VIX_E_MNTAPI_DRIVE_LETTER_ALREADY_ASSIGNED   = 24303,
			VIX_E_MNTAPI_VOLUME_NOT_MOUNTED              = 24304,
			VIX_E_MNTAPI_VOLUME_ALREADY_MOUNTED          = 24305,
			VIX_E_MNTAPI_FORMAT_FAILURE                  = 24306,
			VIX_E_MNTAPI_NO_DRIVER                       = 24307,
			VIX_E_MNTAPI_ALREADY_OPENED                  = 24308,
			VIX_E_MNTAPI_ITEM_NOT_FOUND                  = 24309,
			VIX_E_MNTAPI_UNSUPPROTED_BOOT_LOADER         = 24310,
			VIX_E_MNTAPI_UNSUPPROTED_OS                  = 24311,
			VIX_E_MNTAPI_CODECONVERSION                  = 24312,
			VIX_E_MNTAPI_REGWRITE_ERROR                  = 24313,
			VIX_E_MNTAPI_UNSUPPORTED_FT_VOLUME           = 24314,
			VIX_E_MNTAPI_PARTITION_NOT_FOUND             = 24315,
			VIX_E_MNTAPI_PUTFILE_ERROR                   = 24316,
			VIX_E_MNTAPI_GETFILE_ERROR                   = 24317,
			VIX_E_MNTAPI_REG_NOT_OPENED                  = 24318,
			VIX_E_MNTAPI_REGDELKEY_ERROR                 = 24319,
			VIX_E_MNTAPI_CREATE_PARTITIONTABLE_ERROR     = 24320,
			VIX_E_MNTAPI_OPEN_FAILURE                    = 24321,
			VIX_E_MNTAPI_VOLUME_NOT_WRITABLE             = 24322,

			// Network Errors
			VIX_E_NET_HTTP_UNSUPPORTED_PROTOCOL     = 30001,
			VIX_E_NET_HTTP_URL_MALFORMAT            = 30003,
			VIX_E_NET_HTTP_COULDNT_RESOLVE_PROXY    = 30005,
			VIX_E_NET_HTTP_COULDNT_RESOLVE_HOST     = 30006,
			VIX_E_NET_HTTP_COULDNT_CONNECT          = 30007,
			VIX_E_NET_HTTP_HTTP_RETURNED_ERROR      = 30022,
			VIX_E_NET_HTTP_OPERATION_TIMEDOUT       = 30028,
			VIX_E_NET_HTTP_SSL_CONNECT_ERROR        = 30035,
			VIX_E_NET_HTTP_TOO_MANY_REDIRECTS       = 30047,
			VIX_E_NET_HTTP_TRANSFER                 = 30200,
			VIX_E_NET_HTTP_SSL_SECURITY             = 30201,
			VIX_E_NET_HTTP_GENERIC                  = 30202,
		}

		enum VixVMPowerOpOptions : int
		{
			VIX_VMPOWEROP_NORMAL                    = 0,
			VIX_VMPOWEROP_FROM_GUEST                = 0x0004,
			VIX_VMPOWEROP_SUPPRESS_SNAPSHOT_POWERON = 0x0080,
			VIX_VMPOWEROP_LAUNCH_GUI                = 0x0200,
			VIX_VMPOWEROP_START_VM_PAUSED           = 0x1000,
		}

		enum VixFindItemType : int
		{
			VIX_FIND_RUNNING_VMS    = 1,
			VIX_FIND_REGISTERED_VMS = 4,
		}

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr Vix_GetErrorText(VixError err, string locale);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixHandleType Vix_GetHandleType(IntPtr handle);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixError VixJob_Wait(IntPtr jobHandle,
			VixPropertyID firstPropertyID);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixError VixJob_Wait(IntPtr jobHandle,
			VixPropertyID firstPropertyID,
			ref IntPtr firstProperty,
			VixPropertyID secondPropertyID);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr VixHost_Connect(int apiVersion,
			VixServiceProvider hostType,
			string hostName,
			int hostPort,
			string userName,
			string password,
			VixHostOptions options,
			IntPtr propertyListHandle,
			VixEventProc callbackProc,
			IntPtr clientData);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr VixHost_FindItems(IntPtr hostHandle,
			VixFindItemType searchType,
			IntPtr searchCriteria,
			int timeout,
			VixEventProc callbackProc,
			IntPtr clientData);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern void VixHost_Disconnect(IntPtr hostHandle);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern void Vix_ReleaseHandle(IntPtr handle);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr VixHost_OpenVM(IntPtr hostHandle,
			string vmxFilePathName,
			VixVMOpenOptions options,
			IntPtr propertyListHandle,
			VixEventProc callbackProc,
			IntPtr clientData);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixError VixVM_GetRootSnapshot(IntPtr vmHandle,
			int index,
			ref IntPtr snapshotHandle);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixError VixVM_GetCurrentSnapshot(IntPtr vmHandle,
			ref IntPtr snapshotHandle);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixError VixVM_GetNamedSnapshot(IntPtr vmHandle,
			string name,
			ref IntPtr snapshotHandle);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr VixVM_PowerOn(IntPtr vmHandle,
			VixVMPowerOpOptions powerOnOptions,
			IntPtr propertyListHandle,
			VixEventProc callbackProc,
			IntPtr clientData);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr VixVM_PowerOff(IntPtr vmHandle,
			VixVMPowerOpOptions powerOffOptions,
			VixEventProc callbackProc,
			IntPtr clientData);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr VixVM_RevertToSnapshot(IntPtr vmHandle,
			IntPtr snapshotHandle,
			VixVMPowerOpOptions options,
			IntPtr propertyListHandle,
			VixEventProc callbackProc,
			IntPtr clientData);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixError VixVM_GetNumRootSnapshots(IntPtr vmHandle,
			ref int result);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr VixVM_WaitForToolsInGuest(IntPtr vmHandle,
			int timeoutInSeconds,
			VixEventProc callbackProc,
			IntPtr clientData);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern VixError Vix_GetProperties(IntPtr handle,
			VixPropertyID firstPropertyID,
			ref IntPtr firstProperty,
			VixPropertyID secondPropertyID);

		[DllImport(VixDll, CallingConvention = CallingConvention.Cdecl)]
		private static extern void Vix_FreeBuffer(IntPtr p);

		#endregion

		#region P/Invoke Helpers

		private static string GetErrorText(VixError err)
		{
			IntPtr buf = Vix_GetErrorText(err, null);
			return Marshal.PtrToStringAnsi(buf);
		}

		private static void CheckError(VixError err, VixError ignore = VixError.VIX_OK)
		{
			if (err != VixError.VIX_OK && err != ignore)
				throw new VMwareException(err);
		}

		private static void GetResult(IntPtr jobHandle, VixError ignore = VixError.VIX_OK)
		{
			VixError err = VixJob_Wait(jobHandle, VixPropertyID.VIX_PROPERTY_NONE);
			CloseHandle(ref jobHandle);
			CheckError(err, ignore);
		}

		private static IntPtr GetResultHandle(IntPtr jobHandle)
		{
			IntPtr resultHandle = VixInvalidHandle;

			VixError err = VixJob_Wait(
				jobHandle,
				VixPropertyID.VIX_PROPERTY_JOB_RESULT_HANDLE,
				ref resultHandle,
				VixPropertyID.VIX_PROPERTY_NONE);

			CloseHandle(ref jobHandle);

			CheckError(err);

			return resultHandle;
		}

		private static IntPtr Connect(Provider type, string host, int port, string login, string password)
		{
			IntPtr jobHandle = VixHost_Connect(
				VixApiVersion,
				(VixServiceProvider)type,
				host,
				port,
				login,
				password,
				VixHostOptions.VIX_HOSTOPTION_NONE,
				VixInvalidHandle,
				null,
				IntPtr.Zero);

			return GetResultHandle(jobHandle);
		}

		private static void Disconnect(IntPtr connectionHandle)
		{
			VixHost_Disconnect(connectionHandle);
		}

		private static IntPtr OpenVM(IntPtr hostHandle, string vmx)
		{
			IntPtr jobHandle = VixHost_OpenVM(
				hostHandle,
				vmx,
				VixVMOpenOptions.VIX_VMOPEN_NORMAL,
				VixInvalidHandle,
				null,
				IntPtr.Zero);

			return GetResultHandle(jobHandle);
		}

		private static void VixDiscoveryProc(IntPtr jobHandle, VixEventType eventType, IntPtr moreEventInfo, IntPtr clientData)
		{
			if (eventType != VixEventType.VIX_EVENTTYPE_FIND_ITEM)
				return;

			IntPtr ptr = IntPtr.Zero;
			VixError err = Vix_GetProperties(
				moreEventInfo,
				VixPropertyID.VIX_PROPERTY_FOUND_ITEM_LOCATION,
				ref ptr, VixPropertyID.VIX_PROPERTY_NONE);

			if (err == VixError.VIX_OK)
			{
				GCHandle gch = GCHandle.FromIntPtr(clientData);
				List<string> list = (List<string>)gch.Target;
				list.Add(Marshal.PtrToStringAnsi(ptr));
			}

			Vix_FreeBuffer(ptr);
		}

		private static List<string> ListVMs(IntPtr hostHandle)
		{
			var vms = new List<string>();
			GCHandle gch = GCHandle.Alloc(vms);

			try
			{
				IntPtr jobHandle = VixHost_FindItems(
					hostHandle,
					VixFindItemType.VIX_FIND_REGISTERED_VMS,
					VixInvalidHandle,
					-1,
					VixDiscoveryProc,
					GCHandle.ToIntPtr(gch));

				GetResult(jobHandle);

				return vms;
			}
			finally
			{
				gch.Free();
			}
		}

		private static IntPtr GetSnapshot(IntPtr vmHandle, string name)
		{
			IntPtr snapshotHandle = IntPtr.Zero;

			VixError err = VixVM_GetNamedSnapshot(vmHandle, name, ref snapshotHandle);

			CheckError(err);

			return snapshotHandle;
		}

		private static IntPtr GetSnapshot(IntPtr vmHandle, int index)
		{
			IntPtr snapshotHandle = IntPtr.Zero;

			VixError err = VixVM_GetRootSnapshot(vmHandle, index, ref snapshotHandle);

			CheckError(err);

			return snapshotHandle;
		}

		private static void RevertToSnapshot(IntPtr vmHandle, IntPtr snapshotHandle)
		{
			IntPtr jobHandle = VixVM_RevertToSnapshot(
				vmHandle,
				snapshotHandle,
				VixVMPowerOpOptions.VIX_VMPOWEROP_NORMAL,
				IntPtr.Zero,
				null,
				IntPtr.Zero);

			GetResult(jobHandle);
		}

		private static void PowerOn(IntPtr vmHandle)
		{
			IntPtr jobHandle = VixVM_PowerOn(
				vmHandle,
				VixVMPowerOpOptions.VIX_VMPOWEROP_LAUNCH_GUI,
				IntPtr.Zero,
				null,
				IntPtr.Zero);

			GetResult(jobHandle, VixError.VIX_E_VM_IS_RUNNING);
		}

		private static void PowerOff(IntPtr vmHandle)
		{
			IntPtr jobHandle = VixVM_PowerOff(
				vmHandle,
				VixVMPowerOpOptions.VIX_VMPOWEROP_NORMAL,
				null,
				IntPtr.Zero);

			GetResult(jobHandle, VixError.VIX_E_VM_NOT_RUNNING);
		}

		private static void WaitForTools(IntPtr vmHandle, int timeoutInSeconds)
		{
			IntPtr jobHandle = VixVM_WaitForToolsInGuest(
				vmHandle,
				timeoutInSeconds,
				null,
				IntPtr.Zero);

			GetResult(jobHandle);
		}

		private static void CloseHandle(ref IntPtr handle)
		{
			if (handle == VixInvalidHandle)
				return;

			var type = Vix_GetHandleType(handle);

			switch (type)
			{
				case VixHandleType.VIX_HANDLETYPE_HOST:
					VixHost_Disconnect(handle);
					break;
				case VixHandleType.VIX_HANDLETYPE_VM:
					PowerOff(handle);
					Vix_ReleaseHandle(handle);
					break;
				default:
					Vix_ReleaseHandle(handle);
					break;
			}

			handle = VixInvalidHandle;
		}

		private class VMwareException : PeachException
		{
			public VixError Error { get; private set; }

			public VMwareException(VixError err)
				: base(GetErrorText(err) + " (error: " + (ulong)err + ").")
			{
				this.Error = err;
			}
		}

		#endregion

		public bool WaitForToolsInGuest { get; private set; }
		public bool ResetEveryIteration { get; private set; }
		public int WaitTimeout { get; private set; }
		public string Vmx { get; private set; }
		public string Host { get; private set; }
		public string Login { get; private set; }
		public string Password { get; private set; }
		public Provider HostType { get; private set; }
		public int HostPort { get; private set; }
		public int? SnapshotIndex { get; private set; }
		public string SnapshotName { get; private set; }
		public bool ResetOnFaultBeforeCollection { get; private set; }

		IntPtr hostHandle = VixInvalidHandle;
		IntPtr vmHandle = VixInvalidHandle;
		IntPtr snapshotHandle = VixInvalidHandle;
		bool needReset = true;

		void StartVM()
		{
			if (needReset || ResetEveryIteration)
			{
				try
				{
					logger.Debug("Starting virtual machine \"" + Vmx + "\".");

					try
					{
						if (snapshotHandle != VixInvalidHandle)
							CloseHandle(ref snapshotHandle);

						snapshotHandle = VixInvalidHandle;
					}
					catch (Exception ex)
					{
						logger.Warn("Ignoring exception closing old snapshotHandle: " + ex.Message);
					}

					try
					{
						if (vmHandle != VixInvalidHandle)
							CloseHandle(ref vmHandle);

						vmHandle = VixInvalidHandle;
					}
					catch (Exception ex)
					{
						logger.Warn("Ignoring exception closing old vmHandle: " + ex.Message);
					}

					try
					{
						if (hostHandle != VixInvalidHandle)
							Disconnect(hostHandle);

						hostHandle = VixInvalidHandle;
					}
					catch (Exception ex)
					{
						logger.Warn("Ignoring exception closing old hostHandle: " + ex.Message);
					}

					hostHandle = Connect(HostType, Host, HostPort, Login, Password);

					OpenHandle();
					GetSnapshot();

					RevertToSnapshot(vmHandle, snapshotHandle);
					PowerOn(vmHandle);

					if (WaitForToolsInGuest)
					{
						try
						{
							WaitForTools(vmHandle, WaitTimeout);
						}
						catch (VMwareException vmex)
						{
							if ((ulong)vmex.Error != 3025)
								throw;

							// Note: This exception seems to occur sometimes with workstation + open source tools.
							//       Doesn't happen with ESXi + open source tools in guest.
							//  Also ignoring since this should mean the tools are up (??)

							logger.Warn("Ignoring: The command is not recognized by VMware Tools exception.");
						}
					}

					needReset = false;
				}
				catch (Exception ex)
				{
					logger.Error(ex.Message);
					throw;
				}
			}
		}

		public VmwareMonitor(IAgent agent, string name, Dictionary<string, Variant> args)
			: base(agent, name, args)
		{
			ParameterParser.Parse(this, args);

			if (!SnapshotIndex.HasValue && string.IsNullOrEmpty(SnapshotName))
				throw new PeachException("Either SnapshotIndex or SnapshotName is required.");

			if (SnapshotIndex.HasValue && !string.IsNullOrEmpty(SnapshotName))
				throw new PeachException("Only specify SnapshotIndex or SnapshotName, not both.");

			try
			{
				GetErrorText(VixError.VIX_OK);
			}
			catch (DllNotFoundException ex)
			{
				string msg = "VMWare VIX library could not be found. Ensure VIX API 1.12 has been installed. The SDK download can be found at 'http://www.vmware.com/support/developer/vix-api/'";
				throw new PeachException(msg, ex);
			}
		}

		public override void StopMonitor()
		{
			CloseHandle(ref snapshotHandle);
			CloseHandle(ref vmHandle);
			CloseHandle(ref hostHandle);
		}

		protected void OpenHandle()
		{
			if(hostHandle == VixInvalidHandle)
				hostHandle = Connect(HostType, Host, HostPort, Login, Password);

			try
			{
				vmHandle = OpenVM(hostHandle, Vmx);
			}
			catch (VMwareException ve)
			{
				// When not fount on a remote Host, we get error 43
				if ((ulong)ve.Error != 43 || Host == null)
					throw;

				var vms = ListVMs(hostHandle);
				string msg = string.Format("Could not find vmx '{0}' on host '{1}'.  Available vms are:", Vmx, Host);
				vms.Insert(0, msg);
				msg = string.Join(Environment.NewLine + "\t", vms);

				logger.Error("OpenHandle: " + msg);

				throw new PeachException(msg, ve);
			}
		}

		protected void GetSnapshot()
		{
			if (SnapshotIndex.HasValue)
				snapshotHandle = GetSnapshot(vmHandle, SnapshotIndex.Value);
			else
				snapshotHandle = GetSnapshot(vmHandle, SnapshotName);
		}

		public override void SessionStarting()
		{
			OpenHandle();
			GetSnapshot();
			StartVM();
		}

		public override void SessionFinished()
		{
		}

		public override void IterationStarting(uint iterationCount, bool isReproduction)
		{
			StartVM();
		}

		public override bool IterationFinished()
		{
			return false;
		}

		public override bool DetectedFault()
		{
			return false;
		}

		public override Fault GetMonitorData()
		{
			if (ResetOnFaultBeforeCollection)
				StartVM();

			// This indicates a fault was detected and we should reset the VM.
			needReset = true;

			return null;
		}

		public override bool MustStop()
		{
			return false;
		}

		public override Variant Message(string name, Variant data)
		{
			return null;
		}
	}
}
