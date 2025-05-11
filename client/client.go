package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type NetworkContext struct {
	arpTable        map[string]string   // IP -> MAC
	pendingMessages map[string][]string // IP -> очередь сообщений
	pendingMutex    sync.Mutex
	ipAddress       string
	macAddress      string
	port            string
	conn            net.Conn
}

type NetworkPackage struct {
	DestinationMAC string `json:"destination_mac"`
	SourceMAC      string `json:"source_mac"`
	RequestType    string `json:"request_type"`
	DestinationIP  string `json:"destination_ip"`
	SourceIP       string `json:"source_ip"`
	Data           string `json:"data"`
}

func (ctx *NetworkContext) sendEthernetFrame(destIp string, payload string) {
	routerIp := "localhost"
	_, exists := ctx.arpTable[routerIp]
	if !exists {
		ctx.handleFirstConn(routerIp)
		return
	}
	pkt := NetworkPackage{
		DestinationMAC: "FF:FF:FF:FF:FF:FF",
		SourceMAC:      ctx.macAddress,
		RequestType:    "ETHERNET",
		DestinationIP:  destIp,
		SourceIP:       ctx.ipAddress,
		Data:           payload,
	}
	var destMac string
	destMac, exists = ctx.arpTable[destIp]
	if !exists {
		ctx.pendingMutex.Lock()
		ctx.pendingMessages[destIp] = append(ctx.pendingMessages[destIp], payload)
		ctx.pendingMutex.Unlock()

		if len(ctx.pendingMessages[destIp]) == 1 {
			pkt.RequestType = "ARP REQUEST"
			jsonBytes, err := json.Marshal(pkt)
			if err != nil {
				panic(err)
			}
			jsonBytes = append(jsonBytes, '\n')
			ctx.conn.Write(jsonBytes)
			fmt.Println("sendEthernetFrame: Отправлен ARP-запрос:", string(jsonBytes))
		}

		fmt.Println("sendEthernetFrame: Ожидание ARP-ответа, сообщение будет отправлено автоматически.")
		return
	}
	pkt.DestinationMAC = destMac
	jsonBytes, err := json.Marshal(pkt)
	if err != nil {
		panic(err)
	}
	jsonBytes = append(jsonBytes, '\n')
	ctx.conn.Write(jsonBytes)
	fmt.Printf("sendEthernetFrame: Отправлено сообщение: %s\n", string(jsonBytes))
	return
}

func (ctx *NetworkContext) handleFirstConn(routerIp string) {
	// Отправляем ARP-запрос к роутеру
	pkt := NetworkPackage{
		DestinationMAC: "FF:FF:FF:FF:FF:FF",
		SourceMAC:      ctx.macAddress,
		RequestType:    "ARP REQUEST",
		DestinationIP:  routerIp,
		SourceIP:       ctx.ipAddress,
	}
	jsonBytes, err := json.Marshal(pkt)
	if err != nil {
		panic(err)
	}
	jsonBytes = append(jsonBytes, '\n')
	ctx.conn.Write(jsonBytes)
	fmt.Printf("handleFirstConn: Отправлен ARP-запрос роутеру %s\n", string(jsonBytes))
	return
}

func (ctx *NetworkContext) handleArpRequest(message *NetworkPackage) {
	_, exists := ctx.arpTable[message.SourceIP]
	if !exists {
		ctx.arpTable[message.SourceIP] = message.SourceMAC
	}
	if message.DestinationIP != ctx.ipAddress {
		return
	}
	reply := NetworkPackage{
		DestinationMAC: message.SourceMAC,
		SourceMAC:      ctx.macAddress,
		RequestType:    "ARP REPLY",
		DestinationIP:  message.SourceIP,
		SourceIP:       ctx.ipAddress,
	}
	jsonBytes, err := json.Marshal(reply)
	if err != nil {
		panic(err)
	}
	jsonBytes = append(jsonBytes, '\n')
	ctx.conn.Write(jsonBytes)
	fmt.Println("handleArpRequest: Отправлен ARP-ответ:", string(jsonBytes))
}

func (ctx *NetworkContext) handleArpReply(message *NetworkPackage) {
	ip := message.SourceIP
	mac := message.SourceMAC

	// 💡 Сохраняем MAC-адрес роутера при первом ARP-ответе
	if _, exists := ctx.arpTable[ip]; !exists {
		ctx.arpTable[ip] = mac
		fmt.Println("handleArpReply: Сохранен MAC-адрес для", ip, "→", mac)
	}

	ctx.pendingMutex.Lock()
	pending, found := ctx.pendingMessages[ip]
	if found {
		delete(ctx.pendingMessages, ip)
		for _, payload := range pending {
			ctx.sendEthernetFrame(ip, payload)
		}
	}
	ctx.pendingMutex.Unlock()
}

func (ctx *NetworkContext) receiveMessages(wg *sync.WaitGroup) {
	defer wg.Done()
	routerStream := bufio.NewReader(ctx.conn)
	for {
		jsonString, err := routerStream.ReadString('\n')
		if err != nil {
			fmt.Printf("receiveMessages: Соединение закрыто: %v\n", err)
			return
		}
		var message NetworkPackage
		err = json.Unmarshal([]byte(jsonString), &message)
		if err != nil {
			panic(err)
		}
		//fmt.Printf("receiveMessages: Пришло сообщение: %s\n", jsonString)

		switch message.RequestType {
		case "ARP REPLY":
			ctx.handleArpReply(&message)
		case "ARP REQUEST":
			ctx.handleArpRequest(&message)
		case "ETHERNET":
			fmt.Printf("Сообщение от %s: %s\n", message.SourceIP, message.Data)
		}
	}
}

func (ctx *NetworkContext) sendMessages(reader *bufio.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("sendMessages: Ошибка при чтении из консоли: %v", err)
			continue
		}
		input = strings.TrimSpace(input)
		parts := strings.SplitN(input, " ", 3)
		if parts[0] == "send" && len(parts) == 3 {
			ctx.sendEthernetFrame(parts[1], parts[2])
		} else {
			fmt.Println("sendMessages: Используй команду: send <IP> <сообщение>")
		}
	}
}

func main() {
	args := os.Args
	if len(args) < 3 {
		fmt.Println("main: Использование: go run client.go <MAC> <IP>")
		return
	}
	macAddress := args[1]
	ipAddress := args[2]
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("main: Клиент запущен с IP: %s\n", ipAddress)

	port := 12346
	ctx := NetworkContext{
		ipAddress:       ipAddress,
		macAddress:      macAddress,
		arpTable:        make(map[string]string),
		pendingMessages: make(map[string][]string),
		port:            strconv.Itoa(port),
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		fmt.Println("main: Ошибка при подключении к серверу:", err)
		return
	}
	defer conn.Close()
	ctx.conn = conn

	var wg sync.WaitGroup
	wg.Add(2)
	go ctx.receiveMessages(&wg)
	go ctx.sendMessages(reader, &wg)
	wg.Wait()
}
