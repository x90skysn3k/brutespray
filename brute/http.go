package brute

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteHTTP(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	// Создаем базовую аутентификацию
	auth := user + ":" + password
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	// Создаем HTTP клиент с таймаутом
	client := &http.Client{
		Timeout: timeout,
	}

	// Настраиваем соединение через прокси или интерфейс
	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	// Создаем кастомный транспорт для HTTP клиента
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return cm.Dial(network, addr)
		},
		// Отключаем проверку SSL сертификатов для HTTPS
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client.Transport = transport

	// Определяем схему (HTTP или HTTPS) на основе порта
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	// Формируем URL
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	// Создаем запрос
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, false
	}

	// Добавляем заголовок аутентификации
	req.Header.Add("Authorization", basicAuth)

	// Выполняем запрос
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	// 200 = успешная аутентификация
	// 401 = неверные учетные данные  
	// Другие коды могут указывать на проблемы соединения
	switch resp.StatusCode {
	case 200:
		return true, true
	case 401:
		return false, true
	default:
		// Для других статусов считаем, что соединение прошло успешно, но аутентификация не удалась
		return false, true
	}
} 