![alt text](logo.png "BlueCat Logo")

Samples tools for remotely fingerprinting BlueCat GEN4 appliances and upgrading the BIOS/idrac firmware

This is a community offering on BlueCat labs and as such it provided without support, this software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

# GEN4 Appliance Fingerprinting (gen4.py)
Utilising the REDFISH REST API upon the embedded iDRAC9 (Out of Band management) remotely scans any BlueCat GEN4 hardware appliance for various hardware configuration details

## Usage

```
python3 gen4.py [-h] [--json] idrac username password

idrac       IP Addresss of the GEN4 appliance iDRAC
username    iDRAC username
password    iDRAC password
-h, --help  show this help message and exit
--json      output JSON instead of default stdout
```

## Example output
```
[BlueCat GEN4 BIOS]
BIOS Manufacturer: BlueCat Networks
BIOS Model: BlueCat GEN4-5000
ServiceTag: C2HQ9T2
Express Service Code: 26272099622
Serial number: CNWS3008BE000L
Asset tag: GEN4-5000-UK-PM

[BlueCat GEN4 Appliance Firmware]
BIOS Version: 1.0.2
BIOS Date: 11/13/2018
iDRAC Firmware Version: 3.34.34.34

[BlueCat GEN4 FingerPrint]
BlueCat Appliance Model: BlueCat GEN4-5000
BlueCat SKU Model: BAM-5000/BDDS-75
SystemID LFC: 8e2b
SystemID SYS: 0x88e
Server Generation: 14G
Server OEM chassis: R340
Server OEM class: R340

[BlueCat GEN4 Appliance State]
Current Power state: On
Current System status: OK

[BlueCat GEN4 Configuration]
Appliance CPU type: 1 x Intel(R) Xeon(R) E-2136 CPU @ 3.30GHz
Appliance Memory size: 32 GB

[BlueCat GEN4 Network Cards]
BRCM GbE 5720 2P Embedded
BRCM GbE 2P 5720-t Adapter

[BlueCat GEN4 Logical NIC to MAC Mapping]
eth0                                 6C-2B-59-7C-9F-5D    172.17.44.92    /255.255.255.0    
eth1                                 6C-2B-59-7C-9F-5E   
eth2                                 00-0A-F7-BF-AE-6C   
eth3                                 00-0A-F7-BF-AE-6D   

[BlueCat GEN4-5000 Physical to Logical Mapping - Rear - Left to Right]
Port           MAC                Status    IPv4 Address    Network Mask     
-------------- -----------------  --------- --------------- ---------------  
eth0           6C-2B-59-7C-9F-5D  LinkUp    172.17.44.92    255.255.255.0    
eth1           6C-2B-59-7C-9F-5E  LinkDown                                   
eth2           00-0A-F7-BF-AE-6C  LinkDown                                   
eth3           00-0A-F7-BF-AE-6D  LinkUp  
```

> NOTE :- IP Address and Network Mask will only be populated if the Dell iSM (iDRAC service module) is deployed and appliance is running

## Example JSON output
```
{
  "BIOS Manufacturer": "BlueCat Networks",
  "BIOS Model": "BlueCat GEN4-5000",
  "ServiceTag": "C2HQ9T2",
  "ExpressServiceCode": "26272099622",
  "Serial": "CNWS3008BE000L",
  "Asset": "GEN4-5000-UK-PM",
  "BIOS version": "1.0.2",
  "BIOS Release Date": "11/13/2018",
  "IDRAC version": "3.34.34.34",
  "BlueCat Appliance Model": "BlueCat GEN4-5000",
  "BlueCat SKU Model": "BAM-5000/BDDS-75",
  "SystemID LFC": "8e2b",
  "SystemID SYS": "0x88e",
  "Server Generation": "14G",
  "Model OEM LFC": "R340",
  "Model OEM SYS": "R340",
  "Appliance Power State": "On",
  "Appliance System State": "OK",
  "Appliance CPU": "1 x Intel(R) Xeon(R) E-2136 CPU @ 3.30GHz",
  "Appliance Memory": "32 GB",
  "Network Adapter 1": "BRCM GbE 5720 2P Embedded",
  "Network Adapter 2": "BRCM GbE 2P 5720-t Adapter",
  "Network Adapter 3": "",
  "Network Ports Rear": {
    "eth0": {
      "mac": "6C-2B-59-7C-9F-5D",
      "ip": "172.17.44.92",
      "mask": "255.255.255.0",
      "status": "LinkUp"
    },
    "eth1": {
      "mac": "6C-2B-59-7C-9F-5E",
      "status": "LinkDown"
    },
    "eth2": {
      "mac": "00-0A-F7-BF-AE-6C",
      "status": "LinkDown"
    },
    "eth3": {
      "mac": "00-0A-F7-BF-AE-6D",
      "status": "LinkUp"
    }
  }
}
```
> NOTE :- IP Address and Network Mask will only be populated if the Dell iSM (iDRAC service module) is deployed and appliance is running

# GEN4 Remote BIOS/idrac firmware update (firmwareupdate.py)
Utilising the REDFISH REST API upon the embedded iDRAC9 (Out of Band management) can remotely update the BIOS and IDRAC firmware.

## Prerequists
Before running the firmwareupdate.py tool

Create the following folders; IDRAC, R640 and R340 in the source directory where the tool in being run.
 
Download the latest R640 BIOS to the R640 folder 

http://poweredgec.dell.com/latest_poweredge-14g.html#R640%20BIOS

Download the latest R340 BIOS to the R340 folder 

http://poweredgec.dell.com/latest_poweredge-14g.html#R340%20BIOS

Download the latest iDRAC9 with lifecycle controller firmware to the IDRAC folder 

http://poweredgec.dell.com/latest_poweredge-14g.html#R640%20iDRAC%20with%20Lifecycle%20controller

## Usage

```
python3 firmwareupdate.py [-h] idrac username password

idrac       IP Addresss of the GEN4 appliance iDRAC
username    iDRAC username
password    iDRAC password
-h, --help  show this help message and exit
```


## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## History

v1.00 - Initial Release

v1.01 - Improved SystemID detection, added BIOS release date and Service Express Code to output

v1.02 - Added firmwareupdate.py POC to update any firmware payload via idrac9 redfish

## Credits

B.Shorland

## License

Copyright 2019 BlueCat Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
