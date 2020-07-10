module github.com/andreatulimiero/seg

go 1.14

require (
	github.com/JordiSubira/drkeymockup v0.0.0-20200508131302-092914ed1adb
	github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1
	github.com/golang/mock v1.4.0 // indirect
	github.com/monnand/dhkx v0.0.0-20180522003156-9e5b033f1ac4
	github.com/scionproto/scion v0.5.0
	github.com/songgao/water v0.0.0-20190725173103-fd331bda3f4b
	github.com/vishvananda/netlink v0.0.0-20170924180554-177f1ceba557
	golang.org/x/crypto v0.0.0-20200423211502-4bdfaf469ed5 // indirect
	golang.org/x/sys v0.0.0-20200515095857-1151b9dac4a9 // indirect
	google.golang.org/protobuf v1.23.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/scionproto/scion => github.com/netsec-ethz/scion v0.0.0-20200525140740-897105c810c3
