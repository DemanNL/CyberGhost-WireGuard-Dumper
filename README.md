# CyberGhost-WireGuard-Dumper
Dump the WireGuard config without using the cyberghostvpn client.
This script will produce a valid WireGuard config which you can use to create and start WireGuard tunnels.

# Prerequisites
The only thing you need is the 'x-app-key' value. 
I couldn't find an API call for this value. So I think it is embedded in the client you download, not sure though.

I nabbed the 'x-app-key' value by running the `cyberghostvpn` Linux app through a man-in-the-middle proxy.
The value doesn't change when you uninstall and reinstall the client.

If I find where this value comes from and how to grab it, I'll integrate it in this script.
For now you first have to find the 'x-app-key' value yourself.

# Closing notes
CyberGhost seems to clean up their public keys on a regular basis. This means you will have to generate a new WireGuard config everyday using this script.
