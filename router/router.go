package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sync"
)

var (
	clients         = make(map[string]net.Conn)
	arpTable        = make(map[string]string)
	pendingMessages = make(map[string][]string)
	MuClients       sync.Mutex
	MuArpTable      sync.Mutex
	pendingMutex    sync.Mutex
)

type NetworkPackage struct {
	DestinationMAC string `json:"destination_mac"`
	SourceMAC      string `json:"source_mac"`
	RequestType    string `json:"request_type"`
	DestinationIP  string `json:"destination_ip"`
	SourceIP       string `json:"source_ip"`
	Data           string `json:"data"`
}

func logPanic() {
	pc, _, line, ok := runtime.Caller(2)
	if !ok {
		fmt.Println("logPanic: не удалось получить информацию о месте паники")
		return
	}
	fn := runtime.FuncForPC(pc)
	fmt.Printf("Паника в функции %s, строка %d\n", fn.Name(), line)
}

func logMessage(message *NetworkPackage) {
	//fmt.Printf("Получено сообщение: %+v\n", message)
}

func handleArpRequest(message *NetworkPackage, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logPanic()
			fmt.Printf("handleArpRequest: Паника: %v\n", r)
		}
	}()

	//fmt.Printf("handleArpRequest: Начало обработки ARP-запроса от %s\n", conn.RemoteAddr())
	logMessage(message)

	MuArpTable.Lock()
	senderIp := message.SourceIP
	senderMac := message.SourceMAC
	var destMac string
	_, exists := arpTable[senderIp]
	if !exists {
		MuClients.Lock()
		arpTable[senderIp] = senderMac
		clients[senderMac] = conn
		MuClients.Unlock()
	}
	destMac, exists = arpTable[message.DestinationIP]
	MuArpTable.Unlock()
	if exists {
		//fmt.Printf("handleArpRequest: Хост с IP %s найден в ARP-таблице\n", message.DestinationIP)
		MuClients.Lock()
		message.RequestType = "ARP REPLY"
		message.SourceMAC = destMac
		message.SourceIP = message.DestinationIP
		message.DestinationIP = senderIp
		message.DestinationMAC = senderMac
		jsonBytes, err := json.Marshal(message)
		if err != nil {
			fmt.Printf("handleArpRequest: Ошибка маршалинга ARP-ответа: %v\n", err)
			panic(err)
		}
		fmt.Printf("handleArpRequest: отправляется сообщение %s\n", jsonBytes)
		jsonBytes = append(jsonBytes, '\n')
		clients[senderMac].Write(jsonBytes)
		fmt.Printf("handleArpRequest: Отправлен ARP-ответ для IP %s\n", message.DestinationIP)
		MuClients.Unlock()
		return
	}

	// Если не найден в таблице ARP
	MuClients.Lock()
	_, exists = clients[senderMac]
	if !exists {
		fmt.Printf("handleArpRequest: Нет клиента с таким IP %s\n", senderIp)
		MuClients.Unlock()
		return
	}
	for mac, client := range clients {
		jsonBytes, err := json.Marshal(message)
		if err != nil {
			fmt.Printf("handleArpRequest: Ошибка маршалинга ARP-запроса: %v\n", err)
			panic(err)
		}
		jsonBytes = append(jsonBytes, '\n')
		_, err = client.Write(jsonBytes)
		fmt.Printf("handleArpRequest: отправляю клиенту %s\n", mac)
		if err != nil {
			fmt.Printf("handleArpRequest: Ошибка при рассылке ARP-запроса клиенту %s: %v\n", arpTable[mac], err)
		}
	}
	MuClients.Unlock()
}

func handleArpReply(message *NetworkPackage, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logPanic()
			fmt.Printf("handleArpReply: Паника: %v\n", r)
		}
	}()

	fmt.Printf("handleArpReply: Получен ARP-ответ для %s\n", message.DestinationIP)
	logMessage(message)

	if message.DestinationIP == "localhost" {
		arpTable[message.SourceIP] = message.SourceMAC
		clients[message.SourceMAC] = conn
		fmt.Printf("handleArpReply: Роутер знает о клиенте с IP %s\n", message.SourceIP)
		return
	}

	fmt.Printf("handleArpReply: Отправляю ARP-ответ на %s\n", message.DestinationIP)
	jsonBytes, err := json.Marshal(message)
	if err != nil {
		fmt.Printf("handleArpReply: Ошибка маршалинга ARP-ответа: %v\n", err)
		panic(err)
	}
	jsonBytes = append(jsonBytes, '\n')
	clients[message.DestinationMAC].Write(jsonBytes)
	fmt.Println("handleArpReply: Отправлен ARP-ответ роутеру")
	if conn == nil {
		fmt.Printf("handleArpReply: conn is nil\n")
	}
}

func handleEthernetFrame(message *NetworkPackage) {
	defer func() {
		if r := recover(); r != nil {
			logPanic()
			fmt.Printf("handleEthernetFrame: Паника: %v\n", r)
		}
	}()

	//fmt.Printf("handleEthernetFrame: Обработка Ethernet-кадра от %s\n", message.SourceMAC)
	logMessage(message)

	MuClients.Lock()
	conn, exists := clients[message.DestinationMAC]
	MuClients.Unlock()
	if !exists {
		fmt.Printf("handleEthernetFrame: Клиент с MAC %s не найден\n", message.DestinationMAC)
		return
	}
	jsonBytes, err := json.Marshal(message)
	if err != nil {
		fmt.Printf("handleEthernetFrame: Ошибка маршалинга Ethernet-кадра: %v\n", err)
		panic(err)
	}
	jsonBytes = append(jsonBytes, '\n')
	_, err = conn.Write(jsonBytes)
	if err != nil {
		fmt.Printf("handleEthernetFrame: Ошибка при отправке Ethernet-кадра клиенту %s: %v\n", message.DestinationMAC, err)
		return
	}
	fmt.Printf("handleEthernetFrame: Отправлено сообщение: %s\n", message.Data)
}

func cleanupClient(ip string, mac string, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logPanic()
			fmt.Printf("cleanupClient: Паника: %v\n", r)
		}
	}()

	fmt.Printf("cleanupClient: Клиент IP: %s, MAC: %s отключён\n", ip, mac)
	MuClients.Lock()
	delete(clients, mac)
	MuClients.Unlock()

	MuArpTable.Lock()
	delete(arpTable, ip)
	MuArpTable.Unlock()

	conn.Close()
}

func handleConnection(conn net.Conn) {
	var ip string
	var mac string

	defer func() {
		if r := recover(); r != nil {
			logPanic()
			fmt.Printf("handleConnection: Паника: %v\n", r)
		}
		cleanupClient(ip, mac, conn)
	}()

	reader := bufio.NewReader(conn)

	for {
		//fmt.Printf("handleConnection: Жду новое сообщение от %s\n", conn.RemoteAddr())
		jsonString, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("handleConnection: ReadString err: %v\n", err)
			return
		}
		if jsonString == "" {
			continue
		}

		var message NetworkPackage
		err = json.Unmarshal([]byte(jsonString), &message)
		if err != nil {
			fmt.Println("handleConnection: Проблема с парсингом json:", err)
			panic(err)
		}

		fmt.Printf("handleConnection: Получено сообщение: %s\n", jsonString)

		if ip == "" || mac == "" {
			ip = message.SourceIP
			mac = message.SourceMAC
		}

		switch message.RequestType {
		case "ARP REQUEST":
			handleArpRequest(&message, conn)
		case "ARP REPLY":
			handleArpReply(&message, conn)
		case "ETHERNET":
			handleEthernetFrame(&message)
		default:
			fmt.Printf("handleConnection: Неподдерживаемый запрос: %s\n", message.RequestType)
			return
		}
	}
}

func main() {
	listener, err := net.Listen("tcp", ":12346")
	if err != nil {
		fmt.Println("main: Ошибка при прослушивании:", err)
		return
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port
	done := make(chan struct{})
	routerIp := "localhost"
	routerMac := "00:00:00:00:00:00"
	arpTable[routerIp] = routerMac

	fmt.Printf("main: Сервер слушает на порту: %d\n", port)

	for {
		select {
		case <-done:
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("main: Ошибка при принятии соединения:", err)
				continue
			}
			go handleConnection(conn)
		}
	}
}
