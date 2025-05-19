package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type NetworkPackage struct {
	DNSIP          string `json:"dns_ip"`
	DNSMAC         string `json:"dns_mac"`
	DestinationMAC string `json:"destination_mac"`
	SourceMAC      string `json:"source_mac"`
	RequestType    string `json:"request_type"`
	DestinationIP  string `json:"destination_ip"`
	SourceIP       string `json:"source_ip"`
	HTML           string `json:"html"`
	URL            string `json:"url"`
	Data           string `json:"data"`
}

type dnsEntry struct {
	IP  string
	MAC string
}

var dnsTable = struct {
	sync.RWMutex
	entries map[string]dnsEntry
}{entries: make(map[string]dnsEntry)}

func handleTCP(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	register := NetworkPackage{
		RequestType: "REGISTER_URL",
		SourceIP:    "YOUR_DNS_IP",
		SourceMAC:   "YOUR_DNS_MAC",
		Data:        "example.com",
	}
	if payload, err := json.Marshal(register); err == nil {
		writer.Write(payload)
		writer.WriteByte('\n')
		writer.Flush()
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Ошибка чтения от сервера:", err)
			return
		}
		line = strings.TrimSpace(line)

		var packet NetworkPackage
		if err := json.Unmarshal([]byte(line), &packet); err != nil {
			fmt.Println("Неверный JSON:", err)
			continue
		}

		switch packet.RequestType {
		case "REGISTER_URL":

			dnsTable.Lock()
			dnsTable.entries[packet.Data] = dnsEntry{
				IP:  packet.SourceIP,
				MAC: packet.SourceMAC,
			}
			dnsTable.Unlock()
			fmt.Printf("Зарегистрирован URL: %s → %s (MAC: %s)\n",
				packet.Data, packet.SourceIP, packet.SourceMAC)
			continue
		case "GET_URL":

			handleGetURL(packet, writer)
		default:
			fmt.Printf("Неизвестный тип пакета %q\n", packet.RequestType)
		}
	}
}

func handleGetURL(packet NetworkPackage, writer *bufio.Writer) {
	dnsTable.RLock()
	entry, found := dnsTable.entries[packet.Data]
	dnsTable.RUnlock()

	if !found {
		fmt.Println("URL не зарегистрирован:", packet.Data)
		return
	}

	response := NetworkPackage{
		RequestType:    "GET_URL",
		SourceIP:       entry.IP,
		SourceMAC:      entry.MAC,
		DestinationIP:  packet.SourceIP,
		DestinationMAC: packet.SourceMAC,
		Data:           packet.Data,
	}
	if b, err := json.Marshal(response); err == nil {
		writer.Write(b)
		writer.WriteByte('\n')
		writer.Flush()
	}
}

func main() {
	serverAddr := "127.0.0.1:8000"
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("Не удалось подключиться к", serverAddr, ":", err)
		os.Exit(1)
	}
	fmt.Println("Подключено к серверу", serverAddr)

	handleTCP(conn)
}
