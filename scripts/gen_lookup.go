package main

// Imports
import (
	"os"
	"net"
	"bufio"
	"strings"
	"strconv"
	"encoding/csv"
)

type CachedValue struct {
	Result []string
	Count int
}

// Hold all known cidr ranges
var cache = make(map[*net.IPNet]*CachedValue)

// Checks if a given ip is in cache
func lookupIP(ip net.IP) *CachedValue {

	// Loop each net, if it has ip return true
	for subnet, val := range cache {
		if subnet.Contains(ip) {
			return val
		}
	}

	// Else we don't know it
	return nil

}

// Entry point
func main() {

	// Threshold of ips before saving
	threshold, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}

	// Create a scanner so we can read in line by line
	scanner := bufio.NewScanner(bufio.NewReader(os.Stdin))

	// Resolve the address
	tcpAddr, err := net.ResolveTCPAddr("tcp", "whois.cymru.com:43")
	if err != nil {
		panic(err)
	}

	// Connect to the socket
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		panic(err)
	}

	// Send the begin and verbose
	_, err = conn.Write([]byte("begin\nverbose\n"))
	if err != nil {
		panic(err)
	}

	// Create a reader from the connection and read one line
	_, _, err = bufio.NewReader(conn).ReadLine()
	if err != nil {
		panic(err)
	}

	// Create a new csv reader
	csvReader := csv.NewReader(conn)
	csvReader.Comma = '|'

	// Create a csv writer and write the headers
	csvWriter := csv.NewWriter(os.Stdout)
	csvWriter.Write([]string{"AS", "ASPrefix", "ASCountry", "ASRegistry", "ASAllocDate", "ASName"})
	csvWriter.Flush()

	// Loop each line in file
	for scanner.Scan() {

		// Parse the line as an IP
		ip := net.ParseIP(scanner.Text())

		// Lookup the ip
		val := lookupIP(ip)

		// If it's not known
		if val == nil {

			// Request a lookup on that IP
			_, err = conn.Write([]byte(ip.String() + "\n"))
			if err != nil {
				panic(err)
			}

			// Read the result
			result, err := csvReader.Read()
			if err != nil {
				panic(err)
			}

			// Trim all values
			for key, val := range result {
				result[key] = strings.TrimSpace(val)
			}

			// Parse the response CIDR range
			_, cidr, err := net.ParseCIDR(result[2])
			if err != nil {
				panic(err)
			}

			// Make the ip list
			cache[cidr] = &CachedValue{
				Result: append(result[0:1], result[2:]...),
				Count: 0,
			}
			val = cache[cidr]

		}

		// If we passed the threshold
		if val.Count == threshold {

			// Write the new line
			csvWriter.Write(val.Result)
			csvWriter.Flush()

			// Increment the count to push over the threshold
			val.Count++

		} else {

			// Increment the count
			val.Count++

		}

	}
	
}