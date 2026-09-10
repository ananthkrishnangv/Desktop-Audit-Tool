namespace DesktopAuditTool.Core.Models;

public class HardwareInventory
{
    public string CpuModel { get; set; } = string.Empty;
    public int CpuCores { get; set; }
    public double TotalRamGb { get; set; }
    public string MotherboardManufacturer { get; set; } = string.Empty;
    public string MotherboardProduct { get; set; } = string.Empty;
    public string BiosVersion { get; set; } = string.Empty;
    public bool IsSecureBootEnabled { get; set; }
    public List<StorageDeviceInfo> StorageDevices { get; set; } = [];
    public List<NetworkAdapterInfo> NetworkAdapters { get; set; } = [];
    public List<UsbDeviceInfo> UsbDevices { get; set; } = [];
    public List<string> PeripheralDevices { get; set; } = [];
}

public class StorageDeviceInfo
{
    public string DeviceId { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public double SizeGb { get; set; }
    public string InterfaceType { get; set; } = string.Empty;
    public string MediaType { get; set; } = string.Empty;
    public bool IsEncryptedBitLocker { get; set; }
}

public class NetworkAdapterInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public List<string> IpAddresses { get; set; } = [];
    public List<string> DnsServers { get; set; } = [];
    public string Gateway { get; set; } = string.Empty;
    public bool IsDhcpEnabled { get; set; }
    public string Status { get; set; } = string.Empty;
}

public class UsbDeviceInfo
{
    public string DeviceId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public DateTime? LastConnectedTime { get; set; }
    public bool IsAuthorized { get; set; } = true;
    public string SerialNumber { get; set; } = string.Empty;
}

public class SoftwareInventory
{
    public List<InstalledApplicationInfo> InstalledApplications { get; set; } = [];
    public List<BrowserExtensionInfo> BrowserExtensions { get; set; } = [];
    public List<DriverInfo> Drivers { get; set; } = [];
    public List<RunningServiceInfo> RunningServices { get; set; } = [];
    public List<StartupProgramInfo> StartupPrograms { get; set; } = [];
    public List<LicenseInfo> Licenses { get; set; } = [];
}

public class InstalledApplicationInfo
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string InstallDate { get; set; } = string.Empty;
    public string InstallLocation { get; set; } = string.Empty;
    public bool IsUnauthorized { get; set; }
    public bool IsEndOfLife { get; set; }
}

public class BrowserExtensionInfo
{
    public string Browser { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string ExtensionId { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
}

public class DriverInfo
{
    public string DeviceName { get; set; } = string.Empty;
    public string DriverVersion { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public bool IsSigned { get; set; } = true;
}

public class RunningServiceInfo
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string StartType { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public bool IsUnquotedPath { get; set; }
    public bool IsRiskyService { get; set; }
}

public class StartupProgramInfo
{
    public string Name { get; set; } = string.Empty;
    public string Command { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string User { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
}

public class LicenseInfo
{
    public string ProductName { get; set; } = string.Empty;
    public string LicenseType { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
}

public class UserInventory
{
    public List<UserAccountInfo> LocalUsers { get; set; } = [];
    public List<UserAccountInfo> DomainUsers { get; set; } = [];
    public List<string> PrivilegedUsers { get; set; } = [];
    public List<string> DormantAccounts { get; set; } = [];
    public List<string> SharedAccounts { get; set; } = [];
}

public class UserAccountInfo
{
    public string Username { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
    public bool IsAdministrator { get; set; }
    public bool PasswordNeverExpires { get; set; }
    public DateTime? LastLogin { get; set; }
    public DateTime? PasswordLastSet { get; set; }
    public bool IsDormant { get; set; }
}

public class AssetInventory
{
    public string Hostname { get; set; } = Environment.MachineName;
    public string DomainOrWorkgroup { get; set; } = Environment.UserDomainName;
    public string OsVersion { get; set; } = Environment.OSVersion.ToString();
    public HardwareInventory Hardware { get; set; } = new();
    public SoftwareInventory Software { get; set; } = new();
    public UserInventory Users { get; set; } = new();
}
