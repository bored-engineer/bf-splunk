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
* In the Splunk web interface, from the App menu, select the "Project Bitfl1p" application.
