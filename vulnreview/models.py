from django.db import models

# Most models can have one or more types defined.

class ModelType(models.Model):
    """A base class consisting of a short name and a description.
    Used for defining and assigning types to the various models.
    Nothing uses this directly, but it's inherited by the *Type models."""
    shortName = models.CharField(max_length=50, unique=True)
    description = models.CharField(max_length=250)

    class Meta:
        abstract = True
class DepartmentType(ModelType):
    """Department/group type (e.g. External, internal, self-managed)"""
class ContactType(ModelType):
    """Contact type (e.g. system, network, administrative, hourly)"""
class ScanType(ModelType):
    """Scan type (e.g. production, development, Nessus)"""
class SystemType(ModelType):
    """System type (e.g. virtual, physical, production, test, critical)"""
class ResultType(ModelType):
    """Result type. ...honestly, I have no idea what this could be."""
class NetworkType(ModelType):
    """Network type (e.g. datacenter, external, internal, development, test)"""
class FirewallGroupType(ModelType):
    """Firewall group type (e.g. RDP-vulnerable, SSH-vulnerable, etc.)"""
class VulnerabilityType(ModelType):
    """Vulnerability type (e.g. system, service, local, remote)"""
class PluginType(ModelType):
    """Plugin type (e.g. safe, dangerous, unauthenticated,
    high false-positive)"""
class PluginFamilyType(ModelType):
    """Plugin family type (e.g. local, remote, Windows, OS X)"""
class ClassificationType(ModelType):
    """Classification type (e.g. justification needed, followup needed)"""
class StatusType(ModelType):
    """Status type (e.g. approval required, more information requested)"""



class Department(models.Model):
    """A department or group."""
    deptName = models.CharField(max_length=150, unique=True)
    typeList = models.ManyToManyField("DepartmentType", null=True)

class Contact(models.Model):
    """A person that is responsible for a given system or network."""
    netid = models.CharField(max_length=25, unique=True)
    name = models.CharField(max_length=100)
    typeList = models.ManyToManyField("ContactType", null=True)

class Scan(models.Model):
    """A vulnerability scan."""
    description = models.CharField(max_length=50)
    startTime = models.DateTimeField("Start time")
    scanner = models.ForeignKey("Scanner")
    typeList = models.ManyToManyField("ScanType", null=True)

class System(models.Model):
    """A physical or virtual system that may have vulnerabilities."""
    mac = models.CharField("MAC address")
    interfaceList = models.ManyToManyField("Interface", null=True)
    contactList = models.ManyToManyField("Contact", null=True)
    departmentList = models.ManyToManyField("Department", null=True)
    typeList = models.ManyToManyField("SystemType", null=True)

class Interface(models.Model):
    """A network interface for a system."""
    ip = models.IPAddressField("IP address")
    networkSlice = models.ForeignKey("NetworkSlice")

class Result(models.Model):
    """Result of a scan, for a single system."""
    system = models.ForeignKey("System")
    scan = models.ForeignKey("Scan")
    startTime = models.DateTimeField("Start of scan for system")
    endTime = models.DateTimeField("End of scan for system")
    operatingSystem = models.CharField("Detected OS", max_length=250,
        null=True)
    fqdn = models.CharField("Fully qualified domain name", max_length=150,
        null=True)
    netbiosName = models.CharField("NetBIOS name", max_length=100, null=True)
    sysType = models.CharField("Detected system type", max_length=100,
        null=True)
    typeList = models.ManyToManyField("ResultType", null=True)

class Network(models.Model):
    """A physical or logical network."""
    name = models.CharField("Network name", max_length=150)
    contactList = models.ManyToManyField("Contact", null=True)
    departmentList = models.ManyToManyField("Department", null=True)
    typeList = models.ManyToManyField("NetworkType", null=True)

class NetworkSlice(models.Model):
    """A network segment with a specific firewall group."""
    startIP = models.IPAddressField("Starting IP address")
    endIP = models.IPAddressField("Ending IP address")
    firewallGroup = models.ForeignKey("FirewallGroup")
    typeList = models.ManyToManyField("NetworkType", null=True)
    network = models.ForeignKey("Network")

class FirewallGroup(models.Model):
    """A firewall group."""
    shortName = models.CharField("Group name", max_length=50)
    description = models.CharField("Group description", max_length=250)
    typeList = models.ManyToManyField("FirewallGroupType", null=True)

class Vulnerability(models.Model):
    """A potential vulnerability, as found by Nessus."""

    # From the scan results:
    result = models.ForeignKey("Result")
    plugin = models.ForeignKey("Plugin")
    output = models.TextField("Plugin output")
    port = models.IntegerField("Affected port")
    serviceName = models.CharField("Service name", max_length=50, null=True)

    PROTOCOL_CHOICES = (
        ("T", "TCP"),
        ("U", "UDP"),
        ("I", "ICMP"),
        ("N", "None"),
        ("O", "Other"),
        )

    protocol = models.CharField("Protocol", max_length=1,
        choices=PROTOCOL_CHOICES)

    typeList = models.ManyToManyField("VulnerabilityType", null=True)

    # From the review:
    classification = models.ForeignKey("Classification")
    status = models.ForeignKey("Status")
    followupDate = models.DateField(null=True)
    justification = models.TextField(null=True)
    contactList = models.ManyToManyField("Contact", null=True)

    class Meta:
        verbose_name_plural = "Vulnerabilities"

class Plugin(models.Model):
    """A vulnerability scanner plugin."""

    SEVERITY_CHOICES = (
        ("H", "High"),
        ("M", "Medium"),
        ("L", "Low"),
        ("I", "Informational")
        )

    severity = models.CharField(max_length=1, choices=SEVERITY_CHOICES)
    pluginId = models.IntegerField()
    version = models.CharField(max_length=20)
    pluginName = models.CharField(max_length=150, unique=True)
    pluginFamily = models.CharField(max_length=150)
    typeList = models.ManyToManyField("PluginType", null=True)

    class Meta:
        unique_together = ["pluginId", "version"]

class PluginField(models.Model):
    """Plugins can have different fields."""
    name = models.CharField(max_length=30)

class PluginFieldValue(models.Model):
    """The value of a plugin field."""
    pluginField = models.ForeignKey("PluginField")
    plugin = models.ForeignKey("Plugin")
    value = models.TextField()

class PluginFamily(models.Model):
    """A vulnerability scanner plugin family."""
    shortName = models.CharField(max_length=50)
    description = models.CharField(max_length=150, null=True)
    typeList = models.ManyToManyField("PluginFamilyType", null=True)

    class Meta:
        verbose_name_plural = "Plugin families"

class Classification(models.Model):
    """A potential classification that a vulnerability can be classified as."""
    shortName = models.CharField(max_length=50)
    description = models.CharField(max_length=250, null=True)
    typeList = models.ManyToManyField("ClassificationType", null=True)

class Status(models.Model):
    """A status for this vulnerability as it goes through the lifecycle."""
    shortName = models.CharField(max_length=50)
    description = models.CharField(max_length=250)
    typeList = models.ManyToManyField("StatusType", null=True)

    class Meta:
        verbose_name_plural = "Statuses"

class Scanner(models.Model):
    """A vulnerability scanner."""
    shortName = models.CharField("Short name", max_length=50)
    importEnabled = models.BooleanField("Import enabled",
        help_text="Will be listed as an  "\
                  "option for importing scan"\
                  " results into the app.")
    importModuleName = models.CharField("Module name", max_length=50,
        help_text="Name of module which, "\
                  "given a file, "\
                  "can import it into the DB"\
                  ".")

    def __unicode__(self):
        return self.shortName
