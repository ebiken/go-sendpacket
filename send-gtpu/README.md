# send-gtpu

Tool to send GTP-U packet.

Example: send 8 packets, with TEID 400,401,402,403
# go run send-gtpu.go -count 8 -teid 400-403

# Installation

Modification to support GTP in gopacket is not upstreamed. (yet)
Thus you need to overwrite gopacket with the one in github.com/ebiken/gopacket.

```
$ mkdir -p $GOPATH/github.com/google
$ cd $GOPATH/github.com/google
$ git clone https://github.com/ebiken/gopacket.git
// note: use default branch ebiken-gtp
$ go get github.com/ebiken/go-sendpacket/send-gtpu/
```

