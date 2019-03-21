package metrics

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Helper to prepare metrics to send
func (metrics *Metrics) metricFormat(name string, value int) string {
	return fmt.Sprintf(
		"%s %d %d\n",
		metrics.Tag+"."+name,
		value,
		time.Now().Unix(),
	)
}

// Counter will be used to keep track of a counter
type Counter struct {
	Count    int
	Interval int64
}

// Metrics will be used to send metrics to grafana via TCP or UDP
type Metrics struct {
	mux      sync.Mutex
	Host     string
	Port     int
	Protocol string
	Tag      string
	Timeout  time.Duration
	conn     net.Conn
	Counters map[string]Counter
}

// Contants for times
const defaultTimeout = 5
const defaultInterval = 60
const defaultRetries = 5

// Connect to assign the connection object
func (metrics *Metrics) Connect() error {
	// Make sure the connection isn't open
	if metrics.conn != nil {
		_ = metrics.conn.Close()
	}
	// Prepare connection string
	connString := fmt.Sprintf("%s:%d", metrics.Host, metrics.Port)
	// Check timeout
	if metrics.Timeout == 0 {
		metrics.Timeout = defaultTimeout * time.Second
	}
	var err error
	var conn net.Conn
	var udpAddr *net.UDPAddr
	// Establish connection by type
	if metrics.Protocol == "udp" {
		udpAddr, err = net.ResolveUDPAddr("udp", connString)
		if err != nil {
			return err
		}
		conn, err = net.DialUDP(metrics.Protocol, nil, udpAddr)
	} else {
		conn, err = net.DialTimeout(metrics.Protocol, connString, metrics.Timeout)
	}
	if err != nil {
		return err
	}
	metrics.conn = conn

	return nil
}

// Disconnect closes the connection object
func (metrics *Metrics) Disconnect() error {
	err := metrics.conn.Close()
	metrics.conn = nil

	return err
}

// ConnectAndSend to connect and submit a metric via TCP or UDP
func (metrics *Metrics) ConnectAndSend(name string, value int) {
	err := metrics.Connect()
	if err != nil {
		log.Printf("error connecting %v", err)
	}
	err = metrics.Send(name, value)
	i := 0
	for err != nil {
		log.Printf("Something happened %v", err)
		_ = metrics.Connect()
		err = metrics.Send(name, value)
		if i < defaultRetries {
			i++
		} else {
			log.Printf("Too many retries, exiting")
			break
		}
	}
}

// Send to submit a metric via TCP or UDP
func (metrics *Metrics) Send(name string, value int) error {
	mData := metrics.metricFormat(name, value)
	if metrics.Protocol == "udp" {
		fmt.Fprintf(metrics.conn, mData)
	} else if metrics.Protocol == "tcp" {
		buf := bytes.NewBufferString("")
		buf.WriteString(mData)
		_, err := metrics.conn.Write(buf.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

// Inc to increase the counter for a metric
func (metrics *Metrics) Inc(name string) {
	now := time.Now().Unix()
	// Unlock mutex
	metrics.mux.Lock()
	if c, ok := metrics.Counters[name]; ok {
		if (now - c.Interval) >= defaultInterval {
			c.Count = 0
			c.Interval = now
		} else {
			c.Count++
		}
		metrics.Counters[name] = c
	} else {
		c := Counter{
			Count:    1,
			Interval: now,
		}
		metrics.Counters[name] = c
	}
	value := metrics.Counters[name].Count
	metrics.mux.Unlock()

	// Send value
	metrics.ConnectAndSend(name, value)
}

// CreateMetrics to initialize the metrics struct for TCP or UDP
func CreateMetrics(protocol string, host string, port int, tag string) (*Metrics, error) {
	var m *Metrics
	switch protocol {
	case "tcp":
		m = &Metrics{Host: host, Port: port, Protocol: "tcp", Tag: tag}
	case "udp":
		m = &Metrics{Host: host, Port: port, Protocol: "udp", Tag: tag}
	}
	// Initialize values
	m.Timeout = 0
	m.conn = nil
	m.Counters = make(map[string]Counter)
	// Connect
	err := m.Connect()
	if err != nil {
		return m, err
	}

	return m, nil
}
