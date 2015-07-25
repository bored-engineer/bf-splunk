# [Project Bitfl1p](https://www.bitfl1p.com): bf-splunk
The Splunk application behind Project Bitfl1p

## Installation
* Define the SPLUNK_HOME directory
```shell
export SPLUNK_HOME=/opt/splunk
```
* Clone the `bf-splunk` application
```shell
git clone git@github.com:innoying/bf-splunk.git $SPLUNK_HOME/etc/apps/bf-splunk
```
* (Re)start Splunk so that the app is recognized.
```shell
$SPLUNK_HOME/bin/splunk restart
```
* Optionally install the Splunk_TA_Bro application for bro logs, you may have to patch the BroAutoType in `transforms.conf` to:
```
REGEX = ([a-zA-Z0-9]+)\.[0-9:]+-.[0-9:]+\.log
```
* In the Splunk web interface, from the App menu, select the "Project Bitfl1p" application.

## Queries
Determine type of flip resulting in a connection most commonly
```
index = "bf_www" httpHost != "*.bitfl1p.com" | top dst
```
