"""gen4.py"""
# _author_ = Brian Shorland <bshorland@bluecatnetworks.com>
# _version_ = 1.04

import json
import argparse
import collections
import requests
import urllib3

from termcolor import cprint

urllib3.disable_warnings()

def check_supported_idrac_version(idrac, username, password):
    """Check if iDRAC supportes the Assembly REDFISH schema."""
    response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Assembly' % idrac, verify=False, auth=(username, password))
    if response.status_code != 200:
        return False
    return True

# Return Dell OEM model based on SystemID
def gen4_chassis_model(systemid):
    """on Dell 14G chassis the systemID tends to byteflip the systemID stored in lfcdata[u'Attributes'][u'LCAttributes.1.SystemID']."""
    if systemid in ['2b8e', '2a8e', '298e', '8e29', '8e2b', '8e2a']:
        return str('R340')
    if systemid in ['018e', '8e01']:
        return str('R640')
    return str('Unrecognised BlueCat SystemID')

def parse_systemid(data):
    """Parse the SystemID,get BIOS/Express/SystemID"""
    systemid = "Unknown";
    dellchassis = "Unknown";
    biosreleasedate = "Unknown";
    expressservicecode = "Unknown";
    for i in data.items():
        if i[0] == u'@odata.id' or i[0] == u'@odata.context' or i[0] == u'Links' or i[0] == u'Actions' or i[0] == u'@odata.type' or i[0] == u'Description' or i[0] == u'EthernetInterfaces' or i[0] == u'Storage' or i[0] == u'Processors' or i[0] == u'Memory' or i[0] == u'SecureBoot' or i[0] == u'NetworkInterfaces' or i[0] == u'Bios' or i[0] == u'SimpleStorage' or i[0] == u'PCIeDevices' or i[0] == u'PCIeFunctions':
            pass
        elif i[0] == u'Oem':
            for ii in i[1][u'Dell'][u'DellSystem'].items():
                if ii[0] == u'@odata.context' or ii[0] == u'@odata.type':
                    pass
                else:
                    if ii[0] == "BIOSReleaseDate":
                        biosreleasedate = ii[1]
                    if ii[0] == "SystemID":
                        systemid = hex(ii[1])
                    if ii[0] == "ExpressServiceCode":
                        expressservicecode = ii[1]
    if systemid == "0x88e":
        dellchassis = "R340"
    elif systemid == "0x716":
        dellchassis = "R640"
    return systemid, biosreleasedate, expressservicecode, dellchassis

def appliance_nic_configs(idrac, username, password):
    """ Get Appliance NIC models from Assembly Schema. """
    assembly = check_supported_idrac_version(idrac, username, password)
    nic1 = ""
    nic2 = ""
    nic3 = ""
    if assembly:
        if SYSTEMMODENAME == "BlueCat GEN4-7000":
            response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Assembly/NIC.Integrated.1' % idrac, verify=False, auth=(username, password))
            data = response.json()
            nic1 = data['Model']
        if SYSTEMMODENAME in ["BlueCat GEN4-5000", "BlueCat GEN4-4000", "BlueCat GEN4-2000"]:
            # NIC1 is always seen on the motherboard by BIOS but not the OS, even if this is a fibre model where the card is disabled
            nic1 = "BRCM GbE 5720 2P Embedded"
            # Get NIC in slot1
            response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Assembly/NIC.Slot.1' % idrac, verify=False, auth=(username, password))
            data = response.json()
            if response:
                nic2 = data['Model']
            else:
                response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/NetworkAdapters/NIC.Slot.1' % idrac, verify=False, auth=(username, password))
                data = response.json()
                nic2 = data['Model']
            # Get NIC in slot2
            response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/Assembly/NIC.Slot.2' % idrac, verify=False, auth=(username, password))
            data = response.json()
            try:
                if response:
                   nic3 = data['Model']
                else:
                    response = requests.get('https://%s/redfish/v1/Chassis/System.Embedded.1/NetworkAdapters/NIC.Slot.2' % idrac, verify=False, auth=(username, password))
                    data = response.json()
                    nic3 = data['Model']
            except Exception as myexception:
                # Handle exception is slot2 NIC not present
                if 'not found' not in str(myexception).lower():
                    pass
    else:
        print("\nWARNING :- Upgrade iDRAC-with-Lifecycle-Controller_Firmware for this GEN4 appliance")
        print("iDRAC firmware does not support redfish assembly schema")
    return nic1, nic2, nic3


def main():
    """ Main function."""
    global SYSTEMMODENAME
    parser = argparse.ArgumentParser(description='Fingerprint BlueCat GEN4 appliances using idrac/REDFISH API')
    parser.add_argument("idrac", help="IP Addresss of the appliance iDRAC", type=str)
    parser.add_argument("username", help="iDRAC username", type=str)
    parser.add_argument("password", help="iDRAC password", type=str)
    parser.add_argument("--json", help="output JSON", action="store_true")
    args = parser.parse_args()

    # Get required JSON dumps from RedFish Schemea
    system = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1', verify=False, auth=(args.username, args.password))
    systemdata = system.json()
    lifecycle = requests.get('https://' + args.idrac + '/redfish/v1/Managers/LifecycleController.Embedded.1/Attributes', verify=False, auth=(args.username, args.password))
    lfcdata = lifecycle.json()
    bios = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1/Bios', verify=False, auth=(args.username, args.password))
    biosdata = bios.json()
    idrac = requests.get('https://' + args.idrac + '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes', verify=False, auth=(args.username, args.password))
    idracdata = idrac.json()
    ether = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces', verify=False, auth=(args.username, args.password))
    etherdata = ether.json()

    SYSTEMMODENAME = biosdata[u'Attributes'][u'SystemModelName']
    systemid_lfc = lfcdata[u'Attributes'][u'LCAttributes.1.SystemID']
    systemid_sys, biosreleasedate, expressservicecode, dellchassis = parse_systemid(systemdata)
    systemgen = idracdata[u'Attributes'][u'Info.1.ServerGen']

    assembly = check_supported_idrac_version(args.idrac, args.username, args.password)
    nic1 = "";
    nic2 = "";
    nic3 = "";
    if assembly:
        nic1, nic2, nic3 = appliance_nic_configs(args.idrac, args.username, args.password)

    # Build orderDict of appliance inventory
    d = collections.OrderedDict()
    d["BIOS Manufacturer"] = biosdata[u'Attributes'][u'SystemManufacturer']
    d["BIOS Model"] = biosdata[u'Attributes'][u'SystemModelName']
    d["ServiceTag"] = biosdata[u'Attributes'][u'SystemServiceTag']
    d["expressservicecode"] = expressservicecode
    d["Serial"] = systemdata[u'SerialNumber']
    d["Asset"] = systemdata[u'AssetTag']
    d["BIOS version"] = biosdata[u'Attributes'][u'SystemBiosVersion']
    d["BIOS Release Date"] = biosreleasedate
    d["IDRAC version"] = idracdata[u'Attributes'][u'Info.1.Version']
    if systemid_lfc in ['018e', '8e01'] and systemdata[u'Model'] and SYSTEMMODENAME == "BlueCat GEN4-7000":
        if nic1 != "Intel(R) GbE 4P I350-t rNDC":
            d["BlueCat Appliance Model"] = SYSTEMMODENAME + " Fibre"
        else:
            d["BlueCat Appliance Model"] = SYSTEMMODENAME
        d['BlueCat SKU Model'] = 'BAM-7000/BDDS-125'
    elif systemid_lfc in ['2b8e', '8e2b'] and systemdata[u'Model'] and SYSTEMMODENAME == "BlueCat GEN4-5000":
        if nic2 and nic2 == "Intel(R) 10GbE 2P X710 Adapter":
            d["BlueCat Appliance Model"] = SYSTEMMODENAME + " Fibre"
        else:
            d["BlueCat Appliance Model"] = SYSTEMMODENAME
        d['BlueCat SKU Model'] = 'BAM-5000/BDDS-75'
    elif systemid_lfc in ['2a8e', '8e2a'] and systemdata[u'Model'] and SYSTEMMODENAME == "BlueCat GEN4-4000":
        d['BlueCat Appliance Model'] = SYSTEMMODENAME
        d['BlueCat SKU Model'] = 'BDDS-50'
    elif systemid_lfc in ['298e', '8e29'] and systemdata[u'Model'] and SYSTEMMODENAME == "BlueCat GEN4-2000":
        d['BlueCat Appliance Model'] = SYSTEMMODENAME
        d['BlueCat SKU Model'] = 'BDDS-25'
    else:
        d['BlueCat Appliance Model'] = "UNKNOWN SYSTEM ID"
    d['SystemID LFC'] = systemid_lfc
    d['SystemID SYS'] = systemid_sys
    d['Server Generation'] = systemgen
    d['Model OEM LFC'] = gen4_chassis_model(systemid_lfc)
    d['Model OEM SYS'] = dellchassis
    d['Appliance Power State'] = systemdata[u'PowerState']
    d['Appliance System State'] = systemdata[u'Status'][u'Health']
    d['Appliance CPU'] = str(systemdata[u'ProcessorSummary'][u'Count']) + " x " + systemdata[u'ProcessorSummary'][u'Model']
    d['Appliance Memory'] = biosdata[u'Attributes'][u'SysMemSize']
    d['Network Adapter 1'] = nic1
    d['Network Adapter 2'] = nic2
    d['Network Adapter 3'] = nic3
    if d["BlueCat Appliance Model"] == "BlueCat GEN4-5000 Fibre":
        d['Network Ports Rear'] = collections.OrderedDict()
        # Set physical port ordering for GEN5-5000 fibre
        d['Network Ports Rear']['eth2'] = collections.OrderedDict()
        d['Network Ports Rear']['eth3'] = collections.OrderedDict()
        d['Network Ports Rear']['eth0'] = collections.OrderedDict()
        d['Network Ports Rear']['eth1'] = collections.OrderedDict()
    else:
        # Standard port ordering for anything else
        d['Network Ports Rear'] = collections.OrderedDict()
        d['Network Ports Rear']['eth0'] = collections.OrderedDict()
        d['Network Ports Rear']['eth1'] = collections.OrderedDict()
        d['Network Ports Rear']['eth2'] = collections.OrderedDict()
        d['Network Ports Rear']['eth3'] = collections.OrderedDict()
    nicsd = []
    for i in etherdata[u'Members']:
        for ii in i.items():
            nicdetails = collections.OrderedDict()
            fqdd = (ii[1].split("/")[-1])
            etherm = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/' + fqdd, verify=False, auth=(args.username, args.password))
            ethermdata = etherm.json()
            nicdetails['fqdd'] = fqdd
            nicdetails['Description'] = ethermdata['Description']
            nicdetails['MACAddress'] = ethermdata['MACAddress']
            nicdetails['LinkStatus'] = ethermdata['LinkStatus']
            nicdetails['SpeedMbps'] = ethermdata['SpeedMbps']
            nicdetails['AutoNeg'] = ethermdata['AutoNeg']
            nicdetails['FullDuplex'] = ethermdata['FullDuplex']
            nicdetails['IP'] = ""
            # if Dell ISM is loaded then IP address and mask can be gathered from OS
            try:
                for ether in ethermdata[u'IPv4Addresses']:
                    nicdetails['IP'] = ether['Address']
                    nicdetails['mask'] = ether['SubnetMask']
            except:
                pass
            nicsd.append(nicdetails)
            # print(nicdetails)
    nicssorted = sorted(nicsd, key=lambda i: i['Description'])

    if d["BlueCat Appliance Model"] in ["BlueCat GEN4-7000", "BlueCat GEN4-5000", "BlueCat GEN4-4000", "BlueCat GEN4-2000"]:
        for i in nicssorted:
            if i['Description'] in ['eth0', 'Integrated NIC 1 Port 1 Partition 1', 'Embedded NIC 1 Port 1 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth0']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth0']['ip'] = i['IP']
                    d['Network Ports Rear']['eth0']['mask'] = i['mask']
                    d['Network Ports Rear']['eth0']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth0']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth0']['status'] = i['LinkStatus']
            if i['Description'] in ['eth1', 'Integrated NIC 1 Port 2 Partition 1', 'Embedded NIC 2 Port 1 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth1']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth1']['ip'] = i['IP']
                    d['Network Ports Rear']['eth1']['mask'] = i['mask']
                    d['Network Ports Rear']['eth1']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth1']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth1']['status'] = i['LinkStatus']
            if i['Description'] in ['eth2', 'Integrated NIC 1 Port 3 Partition 1', 'NIC in Slot 1 Port 1 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth2']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth2']['ip'] = i['IP']
                    d['Network Ports Rear']['eth2']['mask'] = i['mask']
                    d['Network Ports Rear']['eth2']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth2']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth2']['status'] = i['LinkStatus']
            if i['Description'] in ['eth3', 'Integrated NIC 1 Port 4 Partition 1', 'NIC in Slot 1 Port 2 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth3']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth3']['ip'] = i['IP']
                    d['Network Ports Rear']['eth3']['mask'] = i['mask']
                    d['Network Ports Rear']['eth3']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth3']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth3']['status'] = i['LinkStatus']

    if d["BlueCat Appliance Model"] == "BlueCat GEN4-5000 Fibre":
        for i in nicssorted:
            if i['Description'] in ['eth0', 'NIC in Slot 2 Port 1 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth0']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth0']['ip'] = i['IP']
                    d['Network Ports Rear']['eth0']['mask'] = i['mask']
                    d['Network Ports Rear']['eth0']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth0']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth0']['status'] = i['LinkStatus']
            if i['Description'] in ['eth1', 'NIC in Slot 2 Port 2 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth1']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth1']['ip'] = i['IP']
                    d['Network Ports Rear']['eth1']['mask'] = i['mask']
                    d['Network Ports Rear']['eth1']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth1']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth1']['status'] = i['LinkStatus']
            if i['Description'] in ['eth2', 'NIC in Slot 1 Port 1 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth2']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth2']['ip'] = i['IP']
                    d['Network Ports Rear']['eth2']['mask'] = i['mask']
                    d['Network Ports Rear']['eth2']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth2']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth2']['status'] = i['LinkStatus']
            if i['Description'] in ['eth3', 'NIC in Slot 1 Port 2 Partition 1']:
                if i['IP']:
                    d['Network Ports Rear']['eth3']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth3']['ip'] = i['IP']
                    d['Network Ports Rear']['eth3']['mask'] = i['mask']
                    d['Network Ports Rear']['eth3']['status'] = i['LinkStatus']
                else:
                    d['Network Ports Rear']['eth3']['mac'] = i['MACAddress']
                    d['Network Ports Rear']['eth3']['status'] = i['LinkStatus']

    # Dump JSON if --json on command line
    if args.json:
        print(json.dumps(d, indent=2))
        exit()

    # Print details to STDOUT
    print('\n[BlueCat GEN4 BIOS]')
    print("BIOS Manufacturer: " + d["BIOS Manufacturer"])
    print("BIOS Model: " + d["BIOS Model"])
    print("ServiceTag: " + d["ServiceTag"])
    print("Express Service Code: " + d['expressservicecode'])
    print("Serial number: " + d["Serial"])
    print("Asset tag: " + d["Asset"])
    print('\n[BlueCat GEN4 Appliance Firmware]')
    print("BIOS Version: " + d["BIOS version"])
    print("BIOS Date: " + d['BIOS Release Date'])
    print("iDRAC Firmware Version: " + d["IDRAC version"])

    print('\n[BlueCat GEN4 FingerPrint]')
    print("BlueCat Appliance Model: " + d["BlueCat Appliance Model"])
    print("BlueCat SKU Model: " + d['BlueCat SKU Model'])
    print("SystemID LFC: " + d['SystemID LFC'])
    print("SystemID SYS: " + d['SystemID SYS'])
    print("Server Generation: " + d['Server Generation'])
    print("Server OEM chassis: " + d['Model OEM LFC'])
    print("Server OEM class: " + d['Model OEM SYS'])

    print('\n[BlueCat GEN4 Appliance State]')
    print("Current Power state: " +d['Appliance Power State'])
    print("Current System status: " +d['Appliance System State'])

    print('\n[BlueCat GEN4 Configuration]')
    print("Appliance CPU type: " + d['Appliance CPU'])
    print("Appliance Memory size: " + d['Appliance Memory'])

    print('\n[BlueCat GEN4 Network Cards]')
    if nic1:
        print(d['Network Adapter 1'])
        # Detect if GEN4-5000 Fibre, if the BIOS incorrectly has the embedded NICs enabled patch the BIOS using REDFISH to DisabledOS
        if ((nic2 and nic3) == "Intel(R) 10GbE 2P X710 Adapter") and d["BlueCat Appliance Model"] == "BlueCat GEN4-5000 Fibre":
            print("Checking " + d['Network Adapter 1'] + " is disabled on " +d["BlueCat Appliance Model"])
            SYSTEMMODENAME = SYSTEMMODENAME + " Fibre"
            biossettings = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1/Bios', verify=False, auth=(args.username, args.password)).json()
            if biossettings['Attributes']['EmbNic1Nic2'] == "DisabledOs":
                cprint((" - " + d['Network Adapter 1'] + " is disabled, valid configuration for GEN4-5000 fibre"), "green")
            elif biossettings['Attributes']['EmbNic1Nic2'] == "Enabled":
                cprint((" - " + d['Network Adapter 1'] + " is enabled, invalid configuration for GEN4-5000 fibre"), "red", attrs=['blink'])
    if nic2:
        print(d['Network Adapter 2'])
    if nic3:
        print(d['Network Adapter 3'])

    print("\n[BlueCat GEN4 Logical NIC to MAC Mapping]")
    if biosdata[u'Attributes'][u'SystemModelName'] in ["BlueCat GEN4-7000", "BlueCat GEN4-5000", "BlueCat GEN4-4000", "BlueCat GEN4-2000"]:
        for i in nicssorted:
            if (SYSTEMMODENAME == "BlueCat GEN4-5000 Fibre") and (i['Description'] in ["Embedded NIC 1 Port 1 Partition 1", "Embedded NIC 2 Port 1 Partition 1"]) and not i['MACAddress']:
                cprint("{:<36} {:<17}".format(i['Description'], "DISABLED (OS) - Valid Config for GEN4-5000 Fibre"), 'white')
            elif (SYSTEMMODENAME == "BlueCat GEN4-5000 Fibre") and (i['Description'] in ["Embedded NIC 1 Port 1 Partition 1", "Embedded NIC 2 Port 1 Partition 1"]) and i['MACAddress']:
                cprint('\nWARNING: embedded network adapters are enabled, invalid configuration for GEN4-5000 Fibre', 'red', attrs=['blink'])
                cprint("{:<36} {:<17}".format(i['Description'], i['MACAddress']), 'red', attrs=['blink'])
            else:
                if i['IP']:
                    cprint("{:<36} {:<20} {:<16}/{:<16} ".format(i['Description'], i['MACAddress'], i['IP'], i['mask']), 'white')
                else:
                    cprint("{:<36} {:<20}".format(i['Description'], i['MACAddress']), 'white')

    print("\n[" + d["BlueCat Appliance Model"] + " Physical to Logical Mapping - Rear - Left to Right]")
    cprint("{:<15}{:<18} {:<10}{:<16}{:<16} ".format("Port", "MAC", "Status", "IPv4 Address", "Network Mask"))
    cprint("{:<15}{:<18} {:<10}{:<16}{:<16} ".format("--------------", "-----------------", "---------", "---------------", "---------------"))
    for nic, details in d['Network Ports Rear'].items():
        try:
            cprint("{:<15}{:<18} {:<10}{:<16}{:<16} ".format(nic, details['mac'], details['status'], details['ip'], details['mask']))
        except:
            cprint("{:<15}{:<18} {:<10}{:<16}{:<16} ".format(nic, details['mac'], details['status'], "", ""))

if __name__ == "__main__":
    main()
