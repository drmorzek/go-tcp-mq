package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

type MessageBroker struct {
	channels map[string]map[chan string]struct{}
	history  map[string][]string
}

type Client struct {
	conn     net.Conn
	channels map[string]chan string
}

var users = map[string]string{}
var usersFile = "users"

var criptoKey = []byte("a very very very very secret key")

func encrypt(key []byte, text string) (string, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	data := []byte(text)
	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, text string) (string, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return "", err
	}

	return string(plaintext), nil

}

func loadUsers() {
	fileBytes, err := os.ReadFile(usersFile)
	if err != nil {
		fmt.Println("Error reading users file:", err)
		return
	}

	fileString, err := decrypt(criptoKey, string(fileBytes))
	if err != nil {
		fmt.Println("Error decript users file:", err)
		return
	}

	err = json.Unmarshal([]byte(fileString), &users)
	if err != nil {
		fmt.Println("Error parsing users file:", err)
		return
	}
}

func saveUsers() {

	data, err := json.Marshal(users)

	if err != nil {
		fmt.Println("Error saving users:", err)
		return
	}

	encryptData, err := encrypt(criptoKey, string(data))
	if err != nil {
		fmt.Println("Error encript users file:", err)
		return
	}

	err = os.WriteFile(usersFile, []byte(encryptData), 0644)
	if err != nil {
		fmt.Println("Error writing to file: ", err)
		return
	}
}

var clients = make(map[string]*Client)

func NewMessageBroker() *MessageBroker {
	return &MessageBroker{
		channels: make(map[string]map[chan string]struct{}),
		history:  make(map[string][]string),
	}
}

func (b *MessageBroker) Subscribe(client *Client, channel string) {
	ch := make(chan string)
	client.channels[channel] = ch

	go func() {
		for len(b.history[channel]) > 0 {
			msg := b.history[channel][0]
			ch <- msg
			b.history[channel] = b.history[channel][1:]
		}
	}()

	if _, ok := b.channels[channel]; !ok {
		b.channels[channel] = make(map[chan string]struct{})
	}
	b.channels[channel][ch] = struct{}{}

	go func() {
		for msg := range ch {
			client.conn.Write([]byte(msg + "\r\n"))
			fmt.Printf("%s -> %v: %s\r\n", channel, client.channels[channel], msg)
		}
	}()
}

func (b *MessageBroker) Unsubscribe(client *Client, channel string) {
	ch, ok := client.channels[channel]
	if ok {
		close(ch)
		delete(client.channels, channel)
	}

	chMap, ok := b.channels[channel]
	if ok {
		delete(chMap, ch)
	}

	if len(b.channels[channel]) == 0 {
		// Удалить историю, если нет подписчиков
		delete(b.history, channel)
	}
}

func (b *MessageBroker) Publish(channel string, message string) {
	// Make sure the channel exists in b.channels
	if _, ok := b.channels[channel]; !ok {
		b.channels[channel] = make(map[chan string]struct{})
	}

	chMap, ok := b.channels[channel]

	if ok {
		for ch := range chMap {
			ch <- message
		}
	}

	// Save the message to history
	b.history[channel] = append(b.history[channel], message)
}

func main() {
	loadUsers()

	listener, err := net.Listen("tcp", ":12345")
	if err != nil {
		panic(err)
	}

	defer listener.Close()

	fmt.Println("Сервер запущен и слушает на :12345")

	broker := NewMessageBroker()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go handleConnection(conn, broker)
	}
}

func clearScreen(conn net.Conn) {
	conn.Write([]byte("\033[2J\033[H"))
}

func handleConnection(conn net.Conn, broker *MessageBroker) {
	defer conn.Close()

	client := &Client{
		conn:     conn,
		channels: make(map[string]chan string),
	}

	reader := bufio.NewReader(conn)

	for {
		authenticated := false
		var usernameInput string
		for !authenticated {

			conn.Write([]byte("Enter reg or auth command: "))
			command, _ := reader.ReadString('\n')
			command = strings.TrimSpace(command)

			parts := strings.Split(command, " ")

			if len(parts) < 3 {
				conn.Write([]byte("Invalid command.\r\n"))
				continue
			}

			usernameInput = parts[1]
			expectedPassword, userExists := users[usernameInput]

			switch strings.ToUpper(parts[0]) {
			case "REG":
				if userExists {
					conn.Write([]byte("This user already exists.\r\n"))
					continue
				}

				users[usernameInput] = parts[2]
				saveUsers()

				clearScreen(conn)

				conn.Write([]byte("You've successfully registered! You can now log in with auth command.\r\n"))
				fmt.Printf("%s зарегистрировался.\r\n", usernameInput)
				continue
			case "AUTH":

				if !userExists || parts[2] != expectedPassword {
					conn.Write([]byte("Password or username incorrect.\r\n"))
					continue
				}

				authenticated = true
				clients[usernameInput] = client

				conn.Write([]byte(usernameInput + " connected\r\n"))

				fmt.Printf("%s подключился.\r\n", usernameInput)

			default:
				conn.Write([]byte("Invalid command.\r\n"))
				continue
			}

			break
		}

		conn.Write([]byte("Authenticated\r\n"))

		for authenticated {
			conn.Write([]byte("> "))
			input, _ := reader.ReadString('\n')
			parts := strings.Split(strings.TrimSpace(input), " ")

			switch strings.ToUpper(parts[0]) {
			case "PUB":
				msg := strings.Join(parts[2:], " ")
				broker.Publish(parts[1], msg)
				fmt.Printf("%s -> %v: %s\r\n", usernameInput, parts[1], msg)
			case "SUB":
				broker.Subscribe(client, parts[1])
			case "HISTORY":
				history := fmt.Sprintf("%v", broker.history[parts[1]])
				conn.Write([]byte(history + "\r\n"))
			case "UNSUB":
				broker.Unsubscribe(client, parts[1])
			case "EXIT":
				authenticated = false
				delete(clients, usernameInput)
				fmt.Printf("%s отключился.\r\n", usernameInput)
				clearScreen(conn)
				continue
			default:
				conn.Write([]byte("Unknown command\r\n"))
				continue
			}
		}

	}

}
