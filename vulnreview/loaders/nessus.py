#!/usr/bin/env python

import datetime

from django.core.management import setup_environ
import settings

setup_environ(settings)

timeFormat = "%a %b %d %H:%M:%S %Y"

from vuln_review.models import Scan, System, Network, Vulnerability,\
    Plugin, PluginFamily, Classification, Status, PluginFieldValue,\
    Scanner, Result, NetworkSlice, FirewallGroup, PluginField


def setupInitialObjects():
    """FOR TESTING - create some basic objects"""
    generalPluginFamily = PluginFamily(shortName="General")
    generalPluginFamily.save()
    openPort = Plugin(severity="I", pluginId=0, version="$Revision 0$",
        pluginName="Open network port detected",
        pluginFamily=generalPluginFamily)
    openPort.save()
    net = Network(name="Test network")
    net.save()
    fw_group = FirewallGroup(shortName="FC", description="Fully Closed")
    fw_group.save()
    ns = NetworkSlice(startIP="130.126.0.0", endIP="130.126.255.255",
        firewallGroup=fw_group, network=net)
    ns.save()
    unreviewed = Classification(shortName="Unreviewed",
        description="Vulnerability has not been reviewed by a system or service"\
                    " admin yet.")
    unreviewed.save()
    unapproved = Status(shortName="Unapproved",
        description="Classification has not been approved by the Security Office"\
                    " yet.")
    unapproved.save()

    scanner = Scanner(shortName="Nessus", importEnabled=True,
        importModuleName="loaders.nessus")
    scanner.save()

    return openPort, net, fw_group, ns, unreviewed, unapproved, scanner

def getTestObjects():
    """FOR TESTING - get some basic objects"""
    openPort = Plugin.objects.filter(pluginName="Open network port "\
                                                "detected")[0]
    net = Network.objects.all()[0]
    fw_group = FirewallGroup.objects.all()[0]
    ns = NetworkSlice.objects.all()[0]
    unreviewed = Classification.objects.all()[0]
    unapproved = Status.objects.all()[0]
    scanner = Scanner.objects.filter(shortName="Nessus")[0]

    return openPort, net, fw_group, ns, unreviewed, unapproved, scanner

from NessusParser.file import loader

l = loader("/home/vladg/Downloads/nessus_report_DC_Prod_Scan__scheduled.nessus")

if not len(Network.objects.all()):
    openPort, net, fw_group, ns, unreviewed, unapproved, scanner\
    = setupInitialObjects()
else:
    openPort, net, fw_group, ns, unreviewed, unapproved,\
    scanner = getTestObjects()

# Create a scan object
scan = Scan(description=l.getScanName(), scanner=scanner)
scan.save()

# Iterate through the hosts
hosts = l.getHosts()
for host in hosts:
    result = Result(scan=scan)

    startTime = host.get("startTime")
    endTime = host.get("endTime")
    if not startTime and endTime:
        # Skip anything without a start and an end.
        continue
    result.startTime = datetime.datetime.strptime(startTime, timeFormat)
    result.endTime = datetime.datetime.strptime(endTime, timeFormat)

    if host.get("operatingSystem"):
        result.operatingSystem = host["operatingSystem"]
    if host.get("fqdn"):
        result.fqdn = host["fqdn"]
    if host.get("netbiosName"):
        result.netbiosName = host["netbiosName"]
    if host.get("macAddress"):
        result.macAddress = host["macAddress"]
    if host.get("sysType"):
        result.sysType = host["sysType"]

    systems = System.objects.filter(ip=host["ipAddress"])
    if not systems:
        if settings.DEBUG:
            print "Adding system %s." % host["ipAddress"]
        system = System()
        system.ip = host["ipAddress"]
        system.networkSlice = ns
        system.save()
    elif len(systems) == 1:
        system = systems[0]
    else:
        raise KeyError("Multiple systems defined with the IP address %s." %
                       host["ipAddress"])

    result.system = system
    result.save()

    if not host.get("vulns"):
        continue

    for vuln in host["vulns"]:
        vulnerability = Vulnerability()
        vulnerability.result = result
        if not vuln.get("pluginID"):
            continue

        if vuln["pluginID"] == "0":
            plugin = openPort
        else:
            pluginVersion = vuln.get("plugin_version", "$Revision 0$")

            plugins = Plugin.objects.filter(pluginId=vuln["pluginID"],
                version=pluginVersion)

            if not plugins:
                if settings.DEBUG:
                    print "Adding plugin %s." % vuln["pluginName"]
                plugin = Plugin()
                plugin_severity_map = {"3": "H", "2": "M", "1": "L", "0": "I"}
                plugin.severity = plugin_severity_map[vuln["severity"]]
                plugin.pluginId = vuln["pluginID"]
                plugin.version = pluginVersion
                plugin.pluginName = vuln["pluginName"]

                pluginFamilies = PluginFamily.objects.filter\
                    (shortName=vuln["pluginFamily"])
                if not pluginFamilies:
                    if settings.DEBUG:
                        print "Adding plugin family %s." % vuln["pluginFamily"]
                    pluginFamily = PluginFamily()
                    pluginFamily.shortName = vuln["pluginFamily"]
                    pluginFamily.save()
                elif len(pluginFamilies) == 1:
                    pluginFamily = pluginFamilies[0]
                else:
                    raise KeyError("Multiple plugin families defined with "\
                                   "the name %s." % vuln["pluginFamily"])
                plugin.pluginFamily = pluginFamily
                plugin.save()
            elif len(plugins) == 1:
                plugin = plugins[0]
            else:
                raise KeyError("Multiple plugins defined with the name %s "
                               "and version %s.") % (vuln["pluginID"],
                                                     vuln["plugin_version"])

            vulnerability.plugin = plugin
            vulnerability.output = vuln.get("plugin_output", "")
            vulnerability.port = vuln.get("port", "0")
            vulnerability.serviceName = vuln.get("svc_name", "Unknown")

            vulnerability_protocol_map = {"tcp": "T", "udp": "U", "icmp": "I",
                                          "none": "N", "other": "O"}
            vulnerability.protocol = vulnerability_protocol_map[
                                     vuln.get("protocol", "other")]
            vulnerability.classification = unreviewed
            vulnerability.status = unapproved
            vulnerability.save()

        for field in vuln["fields"].keys():
            pluginFields = PluginField.objects.filter(name=field)
            if not pluginFields:
                if settings.DEBUG:
                    print "Adding plugin field %s." % field
                pluginField = PluginField(name=field)
                pluginField.save()
            elif len(pluginFields) == 1:
                pluginField = pluginFields[0]
            else:
                raise KeyError("Multiple plugin fields defined with the name"
                               " %s." % field)

            if isinstance(vuln["fields"][field], list):
                for f in vuln["fields"][field]:
                    pluginFieldValue = PluginFieldValue()
                    pluginFieldValue.pluginField = pluginField
                    pluginFieldValue.plugin = plugin
                    pluginFieldValue.value = f
                    pluginFieldValue.save()
            else:
                pluginFieldValue = PluginFieldValue()
                pluginFieldValue.pluginField = pluginField
                pluginFieldValue.plugin = plugin
                pluginFieldValue.value = vuln["fields"][field]
                pluginFieldValue.save()
