package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type UdpContext struct {
	mac          string
	ip           string
	conn         *net.UDPConn
	leaseTime    time.Duration
	leaseExpires time.Time
	leaseMutex   sync.Mutex
}

type DHCPMessage struct {
	Type         string `json:"type"`
	ClientMAC    string `json:"client_mac"`
	RequestedIP  string `json:"requested_ip"`
	OfferedIP    string `json:"offered_ip"`
	ClientIpAddr string `json:"cipaddr"`
	LeaseTime    int    `json:"lease_time"` // минуты
}

const serverPort = 8888

const maxLeaseTime = 1 // из сервера (мин)

func (ctx *UdpContext) getIp() (string, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	})
	if err != nil {
		return "", fmt.Errorf("не удалось открыть сокет: %v", err)
	}
	ctx.conn = conn

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введите желаемый IP или 'auto': ")
	requestedIP, _ := reader.ReadString('\n')
	requestedIP = strings.TrimSuffix(requestedIP, "\n")

	discover := DHCPMessage{
		Type:         "discover",
		ClientMAC:    ctx.mac,
		RequestedIP:  "",
		ClientIpAddr: "0.0.0.0",
	}
	if requestedIP != "auto" {
		discover.RequestedIP = requestedIP
	}
	//fmt.Printf("RequestIp: %s\n", discover.RequestedIP)

	err = ctx.sendDHCPMessage(discover)
	if err != nil {
		return "", fmt.Errorf("ошибка получения offer: %v", err)
	}

	offer, err := ctx.waitDHCPMessage("offer")
	if err != nil {
		return "", fmt.Errorf("ошибка получения offer: %v", err)
	}

	fmt.Printf("Получен OFFER: IP %s\n", offer.OfferedIP)

	request := DHCPMessage{
		Type:         "request",
		ClientMAC:    ctx.mac,
		RequestedIP:  offer.OfferedIP,
		ClientIpAddr: "",
		LeaseTime:    maxLeaseTime,
	}
	err = ctx.sendDHCPMessage(request)
	if err != nil {
		return "", fmt.Errorf("ошибка отправки request: %v", err)
	}

	ack, err := ctx.waitDHCPMessage("ack")
	if err != nil {
		return "", fmt.Errorf("ошибка получения ack: %v", err)
	}

	ctx.ip = ack.OfferedIP
	ctx.leaseTime = time.Duration(ack.LeaseTime) * time.Minute
	ctx.leaseMutex.Lock()
	ctx.leaseExpires = time.Now().Add(ctx.leaseTime)
	ctx.leaseMutex.Unlock()

	fmt.Printf("Получен ACK. IP адрес установлен: %s, аренда %v\n", ctx.ip, ctx.leaseTime)

	go ctx.autoRenewLease()

	return ctx.ip, nil
}

func (ctx *UdpContext) sendDHCPMessage(msg DHCPMessage) error {
	serverAddr := net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: serverPort,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = ctx.conn.WriteToUDP(data, &serverAddr)
	return err
}

func (ctx *UdpContext) waitDHCPMessage(expectedType string) (DHCPMessage, error) {
	buffer := make([]byte, 1024)
	for {
		n, _, err := ctx.conn.ReadFromUDP(buffer)
		if err != nil {
			return DHCPMessage{}, err
		}

		var msg DHCPMessage
		err = json.Unmarshal(buffer[:n], &msg)
		if err != nil {
			continue
		}

		if msg.Type == expectedType && msg.ClientMAC == ctx.mac {
			return msg, nil
		}
	}
}

func (ctx *UdpContext) autoRenewLease() {
	for {
		ctx.leaseMutex.Lock()
		timeLeft := time.Until(ctx.leaseExpires)
		halfTime := ctx.leaseTime / 2
		ctx.leaseMutex.Unlock()

		//fmt.Printf("Проверка продления: осталось %v, половина срока %v\n", timeLeft, halfTime)

		if timeLeft <= halfTime {
			fmt.Println("Отправка запроса на продление аренды")

			req := DHCPMessage{
				Type:         "request",
				ClientMAC:    ctx.mac,
				RequestedIP:  ctx.ip,
				ClientIpAddr: ctx.ip,
				LeaseTime:    int(ctx.leaseTime.Minutes()),
			}

			err := ctx.sendDHCPMessage(req)
			if err != nil {
				fmt.Printf("Ошибка продления аренды: %v\n", err)
				time.Sleep(10 * time.Second)
				continue
			}

			//fmt.Println("Ожидание DHCP ACK на продление...")
			ack, err := ctx.waitDHCPMessage("ack")
			if err != nil {
				fmt.Printf("Ошибка получения ACK при продлении: %v\n", err)
				time.Sleep(10 * time.Second)
				continue
			}

			ctx.leaseMutex.Lock()
			ctx.leaseTime = time.Duration(ack.LeaseTime) * time.Minute
			ctx.leaseExpires = time.Now().Add(ctx.leaseTime)
			ctx.leaseMutex.Unlock()

			fmt.Printf("Аренда продлена до %v\n", ctx.leaseExpires)
		}

		time.Sleep(5 * time.Second)
	}
}
