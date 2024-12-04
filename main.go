package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func main() {
	// eBPFオブジェクトをロード
	socketFilterSpec, err := ebpf.LoadCollectionSpec("socket_filter_kern.o")
	if err != nil {
		log.Printf("eBPF verification error details: %+v", err)
		log.Fatalf("Failed to load socket filter eBPF program: %v", err)
	}
	kprobeSpec, err := ebpf.LoadCollectionSpec("kprobe_inet_bind_kern.o")
	if err != nil {
		log.Fatalf("Failed to load kprobe eBPF program: %v", err)
	}

	socketFilterColl, err := ebpf.NewCollection(socketFilterSpec)
	if err != nil {
		log.Fatalf("Failed to create socket filter eBPF collection: %v", err)
	}
	defer socketFilterColl.Close()

	kprobeColl, err := ebpf.NewCollection(kprobeSpec)
	if err != nil {
		log.Fatalf("Failed to create kprobe eBPF collection: %v", err)
	}
	defer kprobeColl.Close()

	// ネットワークインターフェースを取得
	ifaceName := "ens5" // 適宜変更
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	socketFilterProg := socketFilterColl.Programs["http_filter"]
	if socketFilterProg == nil {
		log.Fatalf("Failed to find socket_filter program")
	}

	// デバッグ用にプログラムの詳細を出力
	log.Println("Available programs in socketFilterColl:")
	for name, prog := range socketFilterColl.Programs {
		log.Printf("  Program: %s, Type: %v", name, prog.Type())
	}
	log.Printf("Socket Filter Program Details:")
	log.Printf("  Name: %s", socketFilterProg.String())
	log.Printf("  Type: %v", socketFilterProg.Type())
	log.Printf("  Interface Index: %d", iface.Index)

	// ソケットを作成
	rawSock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("Failed to create raw socket: %v", err)
	}
	defer unix.Close(rawSock)

	// rawSockを*os.Fileに変換
	file := os.NewFile(uintptr(rawSock), fmt.Sprintf("raw_sock_%d", rawSock))
	if file == nil {
		log.Fatalf("Failed to create os.File from raw socket")
	}
	defer file.Close()

	// AttachSocketFilterの戻り値はerrorのみ
	err = link.AttachSocketFilter(file, socketFilterProg)
	if err != nil {
		log.Fatalf("Failed to attach socket filter: %v", err)
	}
	// sockFilterLinkは存在しないため、Closeできません

	// kprobeをアタッチ
	kprobeProg := kprobeColl.Programs["kprobe_inet_bind"]
	if kprobeProg == nil {
		log.Fatalf("Failed to find kprobe program")
	}

	kprobeLink, err := link.Kprobe("inet_bind", kprobeProg, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kprobeLink.Close()

	// Perfイベントを受信
	portEvents := kprobeColl.Maps["port_events"]
	if portEvents == nil {
		log.Fatalf("Failed to find port_events map")
	}

	httpEvents := socketFilterColl.Maps["http_events"]
	if httpEvents == nil {
		log.Fatalf("Failed to find http_events map")
	}

	// イベントリーダーを作成
	portReader, err := perf.NewReader(portEvents, 4096)
	if err != nil {
		log.Fatalf("Failed to create port events reader: %v", err)
	}
	defer portReader.Close()

	httpReader, err := perf.NewReader(httpEvents, 4096)
	if err != nil {
		log.Fatalf("Failed to create HTTP events reader: %v", err)
	}
	defer httpReader.Close()

	// シグナルを待機
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// イベントを処理
	go func() {
		for {
			record, err := portReader.Read()
			if err != nil {
				if err == unix.EINTR {
					break
				}
				log.Printf("Failed to read port event: %v", err)
				continue
			}

			var port uint16
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &port)
			if err != nil {
				log.Printf("Failed to parse port: %v", err)
				continue
			}
			fmt.Printf("リスニングポート: %d\n", port)
		}
	}()

	go func() {
		for {
			record, err := httpReader.Read()
			if err != nil {
				if err == unix.EINTR {
					break
				}
				log.Printf("Failed to read HTTP event: %v", err)
				continue
			}
			path := string(bytes.Trim(record.RawSample, "\x00"))
			fmt.Printf("HTTPリクエストパス: %s\n", path)
		}
	}()

	<-stop
	fmt.Println("終了します")
}
