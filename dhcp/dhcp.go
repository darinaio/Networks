package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const maxTime int = 1
const cleaningInterval = 2

type DHCPMessage struct {
	Type         string `json:"type"`         // Тип сообщения: discover, offer, request, ack
	ClientMAC    string `json:"client_mac"`   // MAC-адрес клиента
	RequestedIP  string `json:"requested_ip"` // Запрашиваемый IP (для request)
	OfferedIP    string `json:"offered_ip"`   // Предложенный IP (для offer)
	ClientIpAddr string `json:"cipaddr"`      // Действующий IP(у клиента)
	LeaseTime    int    `json:"lease_time"`   // Время аренды
}

type LeaseEntry struct {
	ip      string
	Expires time.Time
}

type IPEntry struct {
	ip   string
	Free bool
}

var (
	wg           sync.WaitGroup
	shutdown     = make(chan struct{})
	allocatedIPs = make(map[string]LeaseEntry) // MAC-адрес -> IP-адрес
	ipMutex      sync.Mutex
)

var ipPool = []IPEntry{
	{ip: "10.0.0.0", Free: true},
	{ip: "10.0.0.1", Free: true},
	{ip: "10.0.0.2", Free: true},
	{ip: "10.0.0.3", Free: true},
}

const serverPort int = 8888

func leaseCleaner() {
	ticker := time.NewTicker(cleaningInterval * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			fmt.Println("Очистка аренды завершена")
			return
		case <-ticker.C:
			ipMutex.Lock()
			now := time.Now()
			for mac, lease := range allocatedIPs {
				if lease.Expires.Before(now) {
					fmt.Printf("Аренда IP %s для %s истекла, освобождаем...\n", lease.ip, mac)
					for i := range ipPool {
						if ipPool[i].ip == lease.ip {
							ipPool[i].Free = true
							break
						}
					}
					delete(allocatedIPs, mac)
				}
			}
			ipMutex.Unlock()
		}
	}
}

func allocateIP(client DHCPMessage) (string, bool) {
	ipMutex.Lock()
	defer ipMutex.Unlock()

	if ipStruct, exists := allocatedIPs[client.ClientMAC]; exists {
		return ipStruct.ip, true
	}

	if client.RequestedIP != "" {
		for i := range ipPool {
			if ipPool[i].ip == client.RequestedIP && ipPool[i].Free {
				ipPool[i].Free = false
				allocatedIPs[client.ClientMAC] = LeaseEntry{
					ip: client.RequestedIP,
				}
				return client.RequestedIP, true
			}
		}
		return "", false
	}

	for i := range ipPool {
		if ipPool[i].Free {
			fmt.Printf("Ip:%s status:%v\n", ipPool[i].ip, ipPool[i].Free)
			ipPool[i].Free = false
			allocatedIPs[client.ClientMAC] = LeaseEntry{
				ip: ipPool[i].ip,
			}
			return ipPool[i].ip, true
		}
	}

	return "", false
}

func renewLease(mac string, duration time.Duration, addr *net.UDPAddr, conn *net.UDPConn, ip string) {
	ipMutex.Lock()
	defer ipMutex.Unlock()

	if lease, ok := allocatedIPs[mac]; ok {
		lease.Expires = time.Now().Add(duration)
		allocatedIPs[mac] = lease
		fmt.Printf("Аренда для %s продлена до %v\n", mac, lease.Expires)
		ack := DHCPMessage{
			Type:      "ack",
			ClientMAC: mac,
			OfferedIP: ip,
			LeaseTime: maxTime,
		}
		sendDHCPMessage(conn, addr, ack)
	} else {
		fmt.Printf("Не найден активный lease для %s\n", mac)
	}
}

func handleClient(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	var message DHCPMessage
	if err := json.Unmarshal(data, &message); err != nil {
		fmt.Printf("Ошибка декодирования сообщения от %v: %v\n", clientAddr, err)
		return
	}

	fmt.Printf("Получено сообщение %s\n", string(data))

	switch message.Type {
	case "discover":
		fmt.Printf("Получен DISCOVER от %s\n", message.ClientMAC)

		ip, ok := allocateIP(message)
		if !ok {
			fmt.Printf("Нет доступных IP-адресов для %s\n", message.ClientMAC)
			return
		}

		offer := DHCPMessage{
			Type:      "offer",
			ClientMAC: message.ClientMAC,
			OfferedIP: ip,
			LeaseTime: maxTime,
		}
		sendDHCPMessage(conn, clientAddr, offer)

	case "request":
		fmt.Printf("Получен REQUEST от %s на IP %s\n", message.ClientMAC, message.RequestedIP)

		ipStruct, exists := allocatedIPs[message.ClientMAC]

		if !exists {
			fmt.Printf("Запрошенный IP %s не соответствует выделенному для %s\n", message.RequestedIP, message.ClientMAC)
			ipMutex.Lock()
			for i := range ipPool {
				if ipPool[i].ip == message.RequestedIP {
					ipPool[i].Free = true
					break
				}
			}
			delete(allocatedIPs, message.ClientMAC)
			ipMutex.Unlock()
			return
		}

		if message.ClientIpAddr == message.RequestedIP {
			renewLease(message.ClientMAC, time.Duration(message.LeaseTime)*time.Minute, clientAddr, conn, message.RequestedIP)
			return
		}

		if ipStruct.ip == message.RequestedIP {
			ack := DHCPMessage{
				Type:      "ack",
				ClientMAC: message.ClientMAC,
				OfferedIP: ipStruct.ip,
				LeaseTime: maxTime,
			}
			duration := time.Minute * time.Duration(message.LeaseTime)
			element := allocatedIPs[message.ClientMAC]
			element.Expires = time.Now().Add(duration)
			allocatedIPs[message.ClientMAC] = element
			sendDHCPMessage(conn, clientAddr, ack)
			fmt.Printf("ACK отправлен для %s на IP %s\n", message.ClientMAC, message.RequestedIP)
		}
	default:
		fmt.Printf("Неизвестный тип сообщения от %s: %s\n", clientAddr, message.Type)
	}
}

func sendDHCPMessage(conn *net.UDPConn, addr *net.UDPAddr, message DHCPMessage) {

	data, err := json.Marshal(message)
	if err != nil {
		fmt.Printf("Ошибка кодирования DHCP-сообщения: %v\n", err)
		return
	}

	if _, err := conn.WriteToUDP(data, addr); err != nil {
		fmt.Printf("Ошибка отправки DHCP-сообщения: %v\n", err)
	} else {
		fmt.Printf("DHCP-сообщение отправлено на %v: %s\n", addr, string(data))
	}
}

func main() {
	addr := net.UDPAddr{
		Port: serverPort,
		IP:   net.IPv4zero,
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println("Ошибка запуска DHCP-сервера:", err)
		return
	}
	defer conn.Close()

	fmt.Println("DHCP-сервер запущен и слушает порт", addr.Port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nЗавершение работы сервера...")
		close(shutdown)
		conn.Close()
		wg.Wait()
		os.Exit(0)
	}()

	go leaseCleaner()
	buffer := make([]byte, 1024)
	for {
		fmt.Printf("Сервер ожидает сообщения...\n")
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Ошибка чтения данных:", err)
			continue
		}

		wg.Add(1)
		go func(clientAddr *net.UDPAddr, data []byte) {
			defer wg.Done()
			handleClient(conn, clientAddr, data)
		}(clientAddr, buffer[:n])
	}
}
