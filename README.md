# RS Agent

An agent for relaying Radiosonde Telemetry and managing upgrades to radiosonde_auto_rx

## Install

Typically, this would be installed on the raspberry Pi that is running radiosonde_auto_rx.

First get the software and install the required libraries.

    $ sudo apt-get install python3 python3-openssl
    $ git clone https://gitlab.com/llnz/rs_agent.git
    $ sudo pip install -r requirements.txt

Create a config.conf file, see the settings below. Temporarily, you will need to ask your server admin
to provide the PEM file to allow access (in future, an access token will be added to the settings). 

Then set up this software to run automatically:

    $ sudo cp rs_agent.service /etc/systemd/system/
    $ sudo systemctl daemon-reload
    $ sudo systemctl enable rs_agent.service
    $ sudo systemctl start rs_agent.service


## Settings

The key settings are in the "[server]" group
 
    [server]
    allow_management=True

This allows the server to upgrade radiosonde_auto_rx, and this software.

Other settings are documented in the config.conf.example file.
