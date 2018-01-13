# Wireshark plugin for MySQL XProtocol 

## Description

A dissector plugin for MySQL XProtocol

## Screen shot 

  ![Screen shot](images/wireshark_xprotocol_demo_01.png?raw=true)

## Requirement

* [MySQL plus X Plugin](https://dev.mysql.com/doc/refman/5.7/en/document-store-setting-up.html)
  * Install or upgrade to MySQL 5.7.12 or higher.
  * Install the X Plugin
* [Wireshark](https://www.wireshark.org/#download)
  * Get Wireshark

## Install and Setup

* Get the xprotocol.lua file. (copy or clone)
* Put the file into the Wireshark plugin folder.
* Run Wireshark.
        
        $ git clone https://github.com/naoto-ogawa/wireshark-plugin-mysql-xprotocol
        $ cp wireshark-plugin-mysql-xprotocol/src/xprotocol.lua ~/.config/wireshark/plugins
        $ wireshark
        
* Check installed correctly.
  * Menu -> About Wireshark -> pugin -> find the xprotocol.lua in the plugin list. 

      ![(*1) install check](images/wireshark_xprotocol_installed.png?raw=true) 

* Start or restart MySQL if necessary.
  * Remember the port of MySQL.
            
            $ mysql.server restart --mysqlx_port=8000
                
  * Note that Wireshark can't work on the default port 33060 on my environment.
* Set the port number of MySQL in the plugin preference.
  * Menu -> Preference -> Protocols -> XPROTOCOL -> server port

      ![(*2) set the port number](images/wireshark_xprotocol_preference.png?raw=true) 


## Examples

You can find a lot of example packets in the data directory.

## Test 

I only tested the plugin with my local MySQL on my local Mac. 

## License

GPL

You should check [Beware the GPL](https://wiki.wireshark.org/Lua/) in the Wireshark Wiki.

## Author

[naoto-ogawa](https://github.com/naoto-ogaaw)

