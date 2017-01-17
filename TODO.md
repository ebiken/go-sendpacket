* create send function for each layer.
    * checksum / length calculation should be done in each layer.
    * ethernet
    * IPv4
    * TCP / UDP
    * GTP-U

* "main" function / application should be built by calling each send functions.
    * sendpacket_udp, sendpacket_gtp etc.
    * range or randum option should go into each main function, since it's difficult to write general app for it. ex: which field should be random / range? loop order?

* app to read file with packet information, and keep sending them in loop.
    * Add "interval" option.
