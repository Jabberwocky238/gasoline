package config

const VMACLen = 6

type VMAC = [VMACLen]byte

var EthBroadcastMAC = VMAC{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
