"""firmwareupdate.py"""
# _author_ = Brian Shorland <bshorland@bluecatnetworks.com>
# _version_ = 1.03

import sys
import re
import os
import argparse
import requests
import urllib3

urllib3.disable_warnings()

def get_firmware_filename(chassis):
    """Given a chassis or idrac parameter
    extract the release from the filename and path, returning both."""
    for file in os.listdir(chassis):
        if file.endswith(".EXE"):
            if chassis in ["R640", "R340"]:
                mysplit = file.rsplit("_")
                release = mysplit[-1]
                release = release[:-4]
                biospath = file
            if chassis == "IDRAC":
                mysplit = file.rsplit("_")
                release = mysplit[-2]
                biospath = file
    return release, biospath

def check_supported_idrac_version(idrac, username, password):
    """Check if iDRAC supportes the Assembly and Simple Update REDFISH schema."""
    url = 'https://%s/redfish/v1/UpdateService'
    response = requests.get(url % idrac, verify=False, auth=(username, password))
    data = response.json()
    try:
        for i in data[u'Actions'][u'#UpdateService.SimpleUpdate'][u'TransferProtocol@Redfish.AllowableValues']:
            return True
    except Exception as myexception:
        print(myexception)
        print("\n- WARNING - iDRAC version does not support the SimpleUpdate REDFISH method")
        return False

def parse_systemid(data):
    """ Parse the systemid using various methods."""
    for items in data.items():
        if items[0] == u'@odata.id' or items[0] == u'@odata.context' or items[0] == u'Links' or items[0] == u'Actions' or items[0] == u'@odata.type' or items[0] == u'Description' or items[0] == u'EthernetInterfaces' or items[0] == u'Storage' or items[0] == u'Processors' or items[0] == u'Memory' or items[0] == u'SecureBoot' or items[0] == u'NetworkInterfaces' or items[0] == u'Bios' or items[0] == u'SimpleStorage' or items[0] == u'PCIeDevices' or items[0] == u'PCIeFunctions':
            pass
        elif items[0] == u'Oem':
            for items2 in items[1][u'Dell'][u'DellSystem'].items():
                if items2[0] == u'@odata.context' or items2[0] == u'@odata.type':
                    pass
                else:
                    if items2[0] == "BIOSReleaseDate":
                        biosreleasedate = items2[1]
                    if items2[0] == "SystemID":
                        systemid = hex(items2[1])
    if systemid == "0x88e":
        dellchassis = "R340"
    elif systemid == "0x716":
        dellchassis = "R640"
    else:
        dellchassis = "Unknown"
    return systemid, biosreleasedate, dellchassis

def upload_image_payload(file_image_name, firmware_image_location, idrac, username, password):
    """ Upload image to iDRAC. """
    print("\nUploading \"%s\" firmware payload to iDRAC" % file_image_name)
    global Location
    global new_FW_version
    global dup_version
    global ETag
    req = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/' % (idrac), auth=(username, password), verify=False)
    filename = file_image_name.lower()
    ImageLocation = firmware_image_location
    dirpath = os.getcwd()
    dirpath = dirpath + ImageLocation
    ImagePath = os.path.join(dirpath, filename)
    ETag = req.headers['ETag']
    url = 'https://%s/redfish/v1/UpdateService/FirmwareInventory' % (idrac)
    files = {'file': (filename, open(ImagePath, 'rb'), 'multipart/form-data')}
    headers = {"if-match": ETag}
    response = requests.post(url, files=files, auth=(username, password), verify=False, headers=headers)
    ddict = response.__dict__
    scontent = str(ddict['_content'])
    if response.status_code == 201:
        print("\nUploaded firmware payload to iDRAC")
    else:
        print("\nFailed to uploaed firmware payload, error is %s" % response)
        print("\nMore details on status code error: %s " % ddict['_content'])
        sys.exit()
    zsearch = re.search("Available.+?,", scontent).group()
    zsearch = re.sub('[",]', "", zsearch)
    new_FW_version = re.sub('Available', 'Installed', zsearch)
    zzsearch = zsearch.find("-")
    zzsearch = zsearch.find("-", zzsearch+1)
    dup_version = zsearch[zzsearch+1:]
    print("Firmware version of uploaded payload is: %s" % dup_version)
    Location = response.headers['Location']

def install_image_payload(idrac, username, password):
    """ tell the iDRAC to run the payload upload."""
    print("\nCreating firmware update job ID")
    url = 'https://%s/redfish/v1/UpdateService/Actions/Oem/DellUpdateService.Install' % (idrac)
    payload = "{\"SoftwareIdentityURIs\":[\"" + Location + "\"],\"InstallUpon\":\""+ "NowAndReboot" +"\"}"
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=payload, auth=(username, password), verify=False, headers=headers)
    job_id_location = response.headers['Location']
    job_id = re.search("JID_.+", job_id_location).group()
    print("%s firmware update job ID successfully created" % job_id)

def main():
    """main function."""
    parser = argparse.ArgumentParser(description='Upgrade idrac firmware to lastest release')
    parser.add_argument("idrac", help="IP Addresss of the appliance iDRAC", type=str)
    parser.add_argument("username", help="iDRAC username", type=str)
    parser.add_argument("password", help="iDRAC password", type=str)
    args = parser.parse_args()

    check = check_supported_idrac_version(args.idrac, args.username, args.password)
    if not check:
        print("\n Unsupported iDRAC release - please contact BlueCat CARE support")
        sys.exit()

    # Get required JSON dumps from RedFish Schemea
    system = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1', verify=False, auth=(args.username, args.password))
    systemdata = system.json()
    lifecycle = requests.get('https://' + args.idrac + '/redfish/v1/Managers/LifecycleController.Embedded.1/Attributes', verify=False, auth=(args.username, args.password))
    lfcdata = lifecycle.json()
    bios = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1/Bios', verify=False, auth=(args.username, args.password))
    biosdata = bios.json()
    idrac = requests.get('https://' + args.idrac + '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes', verify=False, auth=(args.username, args.password))
    idracdata = idrac.json()

    systemmodelname = biosdata[u'Attributes'][u'SystemModelName']
    systemid_lfc = lfcdata[u'Attributes'][u'LCAttributes.1.SystemID']
    systemid_sys, biosreleasedate, dellchassis = parse_systemid(systemdata)

    print("BlueCat Appliance Model:", systemmodelname)
    if (dellchassis not in ['R640', 'R340']) and (systemmodelname not in ['BlueCat GEN4-7000', 'BlueCat GEN4-5000', 'BlueCat GEN4-4000', 'BlueCat GEN4-2000']):
        print("\n Not a BlueCat GEN4 appliance, exiting .....")
        sys.exit()

    print("SystemID LFC:", systemid_lfc)
    print("SystemID SYS:", systemid_sys)
    print("Chassis Model:", dellchassis)

    bios_upgrade = False
    idrac_upgrade = False


    # Get the BIOS release and idrac release
    release, biosfile = get_firmware_filename(dellchassis)
    print("\nAvailable BIOS/iDRAC Release")
    print("BIOS Release: ", release)
    print("BIOS File: ", biosfile)
    idracrelease, idracfile = get_firmware_filename("IDRAC")
    print("BIOS Release: ", idracrelease)
    print("BIOS File: ", idracfile)

    print("\nCurrent BIOS/iDRAC Release")

    if dellchassis in ["R640", "R340"] and idracdata[u'Attributes'][u'Info.1.Version'] < idracrelease:
        print("Can be upgrade to iDRAC " + idracrelease)
        idrac_upgrade = True
    elif dellchassis in ["R640", "R340"] and idracdata[u'Attributes'][u'Info.1.Version'] == idracrelease:
        print("iDRAC version: " + idracdata[u'Attributes'][u'Info.1.Version'] + " (CURRENT)")
    if dellchassis == "R640" and biosdata[u'Attributes'][u'SystemBiosVersion'] < release:
        print("BIOS release: " +biosdata[u'Attributes'][u'SystemBiosVersion'] + " (OLD)")
        print("BIOS release date: ", biosreleasedate)
        print("Can be upgraded to BIOS " + release)
        bios_upgrade = True
    elif dellchassis == "R640" and biosdata[u'Attributes'][u'SystemBiosVersion'] == release:
        print("BIOS release: " + biosdata[u'Attributes'][u'SystemBiosVersion'] + " (CURRENT)")
        print("BIOS release date: ", biosreleasedate)
    if dellchassis == "R340" and biosdata[u'Attributes'][u'SystemBiosVersion'] < release:
        print("BIOS release: " +biosdata[u'Attributes'][u'SystemBiosVersion'] + " (OLD)")
        print("BIOS release date: ", biosreleasedate)
        print("Can be upgraded to BIOS " + release)
        bios_upgrade = True
    elif dellchassis == "R340" and biosdata[u'Attributes'][u'SystemBiosVersion'] == release:
        print("BIOS release: " + biosdata[u'Attributes'][u'SystemBiosVersion'] + " (CURRENT)")
        print("BIOS release date: ", biosreleasedate)

    if idrac_upgrade:
        upgrade = input("\nUpgrade to new IDRAC image?")
        upgrade = upgrade.lower()
        if upgrade == "yes":
            upload_image_payload(idracfile, "/IDRAC", args.idrac, args.username, args.password)
            install_image_payload(args.idrac, args.username, args.password)
            print("Appliance rebooting and applying new BIOS firmware")
            sys.exit()

    if bios_upgrade and dellchassis == "R340":
        upgrade = input("\nUpgrade to new BIOS image?")
        upgrade = upgrade.lower()
        if upgrade == "yes":
            upload_image_payload(biosfile, "/R340", args.idrac, args.username, args.password)
            install_image_payload(args.idrac, args.username, args.password)
            print("Appliance rebooting and applying new BIOS firmware")
            sys.exit()

    if bios_upgrade and dellchassis == "R640":
        upgrade = input("\nUpgrade to new BIOS image?")
        upgrade = upgrade.lower()
        if upgrade == "yes":
            upload_image_payload(biosfile, "/R640", args.idrac, args.username, args.password)
            install_image_payload(args.idrac, args.username, args.password)
            print("Appliance rebooting and applying new BIOS firmware")
            sys.exit()


if __name__ == "__main__":
    main()
