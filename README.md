# Sniffler
A simple CLI [packet sniffer](https://en.wikipedia.org/wiki/Packet_analyzer) written in [C](https://en.wikipedia.org/wiki/C_(programming_language)).

Video Demonstration: https://www.youtube.com/watch?v=gkRJeDjVkAU

## Usage
`sudo ./sniffler [OPTIONS]`

Options:

    -q, --no-log                 Disable file logging of packet details
    -s <protocols>, 
    --select=<protocols>, 
    --only=<protocols>           Specify which protocols to log (comma-separated). Valid protocols:
                                 TCP, UDP, ARP, ICMP, IGMP, DNS, HTTP, OTHER
    -o, --out=<filename>         Specify a custom filename for the log output (default is 'log.txt')
                                 This option is useless when the -q option is also specified
    -i, --interface=<interface>  Bind to a specific network interface (e.g., eth0, enp4s0, etc.)
                                 Default is no interface binding (uses first available)
Examples:

    sudo ./sniffler --only=TCP,UDP --out=logfile.txt -i eth0
    sudo ./sniffler -q
    sudo ./sniffler --interface=eth0
    sudo ./sniffler --only=dns --out=my_dns_packets.log

## Supported Packet Types
All supported packet types are listed in `types/`.

| Protocol | Supported |
|:--------:|:---------:|
|   TCP    |     ✔     |
|   UDP    |     ✔     |
|   ARP    |     ✔     |
|   ICMP   |     ✔     |
|   IGMP   |     ✔     |
|   DNS    |     ✔     |
|   HTTP   |     ✔     |
