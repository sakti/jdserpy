jdserpy
=======

java deserialization in network traffic


Requirements
------------

- pcapy
- Impacket
- javaobj


Usage
-----

::

   Usage: jdserpy.py [options]

   Options:
      -h, --help            show this help message and exit
      -i INPUT_RES, --input=INPUT_RES
      --live   


From pcap file
::

    $ ./jdserpy.py -i <pcap file>


or live capture

::

    # ./jdserpy.py -i eth0 --live
