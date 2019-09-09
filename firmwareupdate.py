# _author_ = Brian Shorland <bshorland@bluecatnetworks.com>
# _version_ = 1.02

import sys
import re,time, os
from datetime import datetime
import requests
import json
import urllib3
import argparse
import subprocess

urllib3.disable_warnings()

# idrac_release = "3.34.34.34"
# idrac_filename = "iDRAC-with-Lifecycle-Controller_Firmware_3HT97_WN64_3.34.34.34_A00.EXE"
# idrac_location = "/iDRAC"
# bios_release_r640 = "2.2.11"
# bios_filename_r640 = "BIOS_NM8WY_WN64_2.2.11.EXE"
# bios_location_r640 = "/R640"
# bios_release_r340 = "1.2.0"
# bios_filename_r340 = "BIOS_76NP7_WN64_1.2.0.EXE"
# bios_location_r340 = "/R340"

# Given a chassis or idrac parameter, extract the release from the filename and path, returning both
def get_firmware_filename(chassis):
    for file in os.listdir(chassis):
        if file.endswith(".EXE"):
            if chassis in ["R640","R340"]:
                mysplit=file.rsplit("_")
                release = mysplit[-1]
                release = release[:-4]
                biospath = file
            if chassis == "IDRAC":
                mysplit=file.rsplit("_")
                release = mysplit[-2]
                biospath = file
    return release,biospath

# Check if iDRAC supportes the Assembly and Simple Update REDFISH schema
def check_supported_idrac_version(idrac,username,password):
    response = requests.get('https://%s/redfish/v1/UpdateService' % idrac,verify=False,auth=(username,password))
    data = response.json()
    try:
        for i in data[u'Actions'][u'#UpdateService.SimpleUpdate'][u'TransferProtocol@Redfish.AllowableValues']:
            return True
    except:
        print("\n- WARNING - iDRAC version does not support the SimpleUpdate REDFISH method")
        return False

# Check if the idrac is responding to ping
def check_idrac_lost_connection():
    while True:
        ping_command = "ping %s -n 2" % idrac_ip
        ping_output = subprocess.Popen(ping_command, stdout = subprocess.PIPE, shell=True).communicate()[0]
        ping_results = re.search("Lost = .", ping_output).group()
        if ping_results == "Lost = 0":
            break
        else:
            print("\n- WARNING, iDRAC connection lost due to slow network connection or component being updated requires iDRAC reset. Script will recheck iDRAC connection in 3 minutes")
            time.sleep(180)

def parse_systemID(data):
    # SystemID is also stored in redfish/v1/Systems/System.Embedded.1 under the Oem/Dell branch but in decimal
    # This doesn't seem to byteflip and once converted back to base 16 matches the packages.xml in the linux BIOS packages
    # Also grab the Express Service code and BIOS release date, system generation
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
                        systemID = hex(ii[1])
                    if ii[0] == "ExpressServiceCode":
                        ExpressServiceCode = ii[1]
    if systemID == "0x88e":
        dellchassis = "R340"
    elif systemID == "0x716":
        dellchassis = "R640"
    else:
        dellchassis = "Unknown"
    return systemID,biosreleasedate,ExpressServiceCode,dellchassis

def upload_image_payload(file_image_name, firmware_image_location, idrac, username, password):
    print("\nUploading \"%s\" firmware payload to iDRAC" % file_image_name)
    global Location
    global new_FW_version
    global dup_version
    global ETag
    req = requests.get('https://%s/redfish/v1/UpdateService/FirmwareInventory/' % (idrac), auth=(username, password), verify=False)
    statusCode = req.status_code
    data = req.json()
    filename = file_image_name.lower()
    ImageLocation = firmware_image_location
    dirpath = os.getcwd()
    dirpath = dirpath + ImageLocation
    ImagePath = os.path.join(dirpath, filename)
    ETag = req.headers['ETag']
    url = 'https://%s/redfish/v1/UpdateService/FirmwareInventory' % (idrac)
    files = {'file': (filename, open(ImagePath, 'rb'), 'multipart/form-data')}
    headers = {"if-match": ETag}
    response = requests.post(url, files=files, auth = (username, password), verify=False, headers=headers)
    d = response.__dict__
    s=str(d['_content'])
    if response.status_code == 201:
        print("\nUploaded firmware payload to iDRAC")
    else:
        print("\nFailed to uploaed firmware payload, error is %s" % response)
        print("\nMore details on status code error: %s " % d['_content'])
        sys.exit()
    d = response.__dict__
    z=re.search("Available.+?,",s).group()
    z = re.sub('[",]',"",z)
    new_FW_version = re.sub('Available','Installed',z)
    zz=z.find("-")
    zz=z.find("-",zz+1)
    dup_version = z[zz+1:]
    print("Firmware version of uploaded payload is: %s" % dup_version)
    Location = response.headers['Location']

def install_image_payload(idrac, username, password):
    global job_id
    print("\nCreating firmware update job ID")
    url = 'https://%s/redfish/v1/UpdateService/Actions/Oem/DellUpdateService.Install' % (idrac)
    payload = "{\"SoftwareIdentityURIs\":[\"" + Location + "\"],\"InstallUpon\":\""+ "NowAndReboot" +"\"}"
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=payload, auth = (username, password), verify=False, headers=headers)
    d=str(response.__dict__)
    job_id_location = response.headers['Location']
    job_id = re.search("JID_.+",job_id_location).group()
    print("%s firmware update job ID successfully created" % job_id)


def main():
    global systemModelName
    parser = argparse.ArgumentParser(description='Upgrade idrac firmware to lastest release')
    parser.add_argument("idrac", help="IP Addresss of the appliance iDRAC",type=str)
    parser.add_argument("username", help="iDRAC username",type=str)
    parser.add_argument("password", help="iDRAC password",type=str)
    args = parser.parse_args()

    check = check_supported_idrac_version(args.idrac,args.username,args.password)
    if not check:
        print("\n Unsupported iDRAC release - please contact BlueCat CARE support")
        sys.exit()

    # Get required JSON dumps from RedFish Schemea
    system = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1',verify=False,auth=(args.username,args.password))
    systemData = system.json()
    lifecycle = requests.get('https://' + args.idrac + '/redfish/v1/Managers/LifecycleController.Embedded.1/Attributes', verify=False,auth=(args.username,args.password))
    lfcData = lifecycle.json()
    bios = requests.get('https://' + args.idrac + '/redfish/v1/Systems/System.Embedded.1/Bios',verify=False,auth=(args.username,args.password))
    biosData = bios.json()
    idrac = requests.get('https://' + args.idrac + '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes',verify=False,auth=(args.username,args.password))
    idracData = idrac.json()

    systemModelName = biosData[u'Attributes'][u'SystemModelName']
    systemID_lfc = lfcData[u'Attributes'][u'LCAttributes.1.SystemID']
    systemID_sys,biosreleasedate,ExpressServiceCode,dellchassis = parse_systemID(systemData)
    systemGEN = idracData[u'Attributes'][u'Info.1.ServerGen']

    print("BlueCat Appliance Model:", systemModelName)
    if (dellchassis not in ['R640','R340']) and (systemModelName not in ['BlueCat GEN4-7000','BlueCat GEN4-5000','BlueCat GEN4-4000','BlueCat GEN4-2000']):
        print("\n Not a BlueCat GEN4 appliance, exiting .....")
        sys.exit()

    print("SystemID LFC:", systemID_lfc)
    print("SystemID SYS:", systemID_sys)
    print("Chassis Model:", dellchassis)

    bios_upgrade = False
    idrac_upgrade = False


    # Get the BIOS release and idrac release
    release,biosfile = get_firmware_filename(dellchassis)
    print("\nAvailable BIOS/iDRAC Release")
    print("BIOS Release: ", release)
    print("BIOS File: ", biosfile)
    idracrelease,idracfile = get_firmware_filename("IDRAC")
    print("BIOS Release: ", idracrelease)
    print("BIOS File: ", idracfile)

    print("\nCurrent BIOS/iDRAC Release")

    if (dellchassis in ["R640","R340"] and idracData[u'Attributes'][u'Info.1.Version'] < idracrelease):
        print("Can be upgrade to iDRAC " + idracrelease)
        idrac_upgrade = True
    elif (dellchassis in ["R640","R340"] and idracData[u'Attributes'][u'Info.1.Version'] == idracrelease):
        print("iDRAC version: " +idracData[u'Attributes'][u'Info.1.Version'] + " (CURRENT)")
    if ((dellchassis == "R640" and (biosData[u'Attributes'][u'SystemBiosVersion'] < release))):
        print("BIOS release: " +biosData[u'Attributes'][u'SystemBiosVersion'] + " (OLD)")
        print("BIOS release date: ", biosreleasedate)
        print("Can be upgraded to BIOS " + release)
        bios_upgrade = True
    elif ((dellchassis == "R640" and (biosData[u'Attributes'][u'SystemBiosVersion'] == release))):
        print("BIOS release: " +biosData[u'Attributes'][u'SystemBiosVersion'] + " (CURRENT)")
        print("BIOS release date: ", biosreleasedate)
    if ((dellchassis == "R340" and (biosData[u'Attributes'][u'SystemBiosVersion'] < release))):
        print("BIOS release: " +biosData[u'Attributes'][u'SystemBiosVersion'] + " (OLD)")
        print("BIOS release date: ", biosreleasedate)
        print("Can be upgraded to BIOS " + release)
        bios_upgrade = True
    elif ((dellchassis == "R340" and (biosData[u'Attributes'][u'SystemBiosVersion'] == release))):
        print("BIOS release: " +biosData[u'Attributes'][u'SystemBiosVersion'] + " (CURRENT)")
        print("BIOS release date: ", biosreleasedate)

    if idrac_upgrade:
        x = input("\nUpgrade to new IDRAC image?")
        x = x.lower()
        if x == "yes":
            upload_image_payload(idracfile, "/IDRAC", args.idrac, args.username, args.password)
            install_image_payload(args.idrac, args.username, args.password)
            print("Appliance rebooting and applying new BIOS firmware")
            sys.exit()

    if bios_upgrade and dellchassis == "R340":
        x = input("\nUpgrade to new BIOS image?")
        x = x.lower()
        if x == "yes":
            upload_image_payload(biosfile, "/R340", args.idrac, args.username, args.password)
            install_image_payload(args.idrac, args.username, args.password)
            print("Appliance rebooting and applying new BIOS firmware")
            sys.exit()

    if bios_upgrade and dellchassis == "R640":
        x = input("\nUpgrade to new BIOS image?")
        x = x.lower()
        if x == "yes":
            upload_image_payload(biosfile, "/R640", args.idrac, args.username, args.password)
            install_image_payload(args.idrac, args.username, args.password)
            print("Appliance rebooting and applying new BIOS firmware")
            sys.exit()


if __name__ == "__main__":
    main()
