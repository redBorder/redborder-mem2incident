package main

import (
  "bufio"
  "crypto/tls"
  "encoding/json"
  "fmt"
  "log"
  "net"
  "os"
  "regexp"
  "strings"
  "time"

  "github.com/bradfitz/gomemcache/memcache"
  "github.com/go-resty/resty/v2"
  "gopkg.in/yaml.v2"
)

// Program version
const version = "1.0.0"

// Config structure to hold the configuration
type Config struct {
  MemcachedServer    string `yaml:"memcached_server"`
  ApiEndpoint        string `yaml:"api_endpoint"`
  LoopInterval       int    `yaml:"loop_interval"`        // Interval in seconds
  InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // Ignore TLS verification
  AuthToken          string `yaml:"auth_token"`           // Authentication token
}

// Function to read and parse the configuration file
func readConfig(configFile string) (*Config, error) {
  data, err := os.ReadFile(configFile)
  if err != nil {
    return nil, fmt.Errorf("failed to read config file: %v", err)
  }

  var config Config
  err = yaml.Unmarshal(data, &config)
  if err != nil {
    return nil, fmt.Errorf("failed to parse config file: %v", err)
  }

  return &config, nil
}

// Function to clean up and validate the value obtained from Memcached
func cleanValue(rawValue []byte) string {
  rawString := string(rawValue)
  re := regexp.MustCompile(`{.*}`)
  match := re.FindString(rawString) 

  if match != "" {
    fmt.Println("Clean JSON:", match)
    return match
  } else {
    fmt.Println("No valid JSON was found")
    return rawString
  }
}

func main() {
  // Check if the program was called with the "version" argument
  if len(os.Args) > 1 && os.Args[1] == "version" {
    fmt.Printf("redborder-mem2incident version %s\n", version)
    return
  }

  // Read the configuration
  config, err := readConfig("config.yml")
  if err != nil {
    log.Fatalf("Error reading config: %v", err)
  }

  // Create a new Memcached client
  mc := memcache.New(config.MemcachedServer)

  // Infinite loop to keep the service running
  for {
    // Get all keys from Memcached
    keys, err := getAllKeysFromMemcached(config.MemcachedServer)
    if err != nil {
      log.Printf("Error getting keys: %v", err)
      continue
    }

    for _, key := range keys {
      // Check if the key matches the pattern
      if match, _ := regexp.MatchString(`^rbincident_([a-fA-F0-9\-]+)_incident_([a-fA-F0-9\-]+)$`, key); match {
        log.Printf("Getting key %s", key)

        // Get the value from Memcached
        item, err := mc.Get(key)

        if err != nil {
          log.Printf("Error getting key %s: %v", key, err)
          continue
        }
        // Deserialize escaped JSON
        var jsonEscaped string
        err = json.Unmarshal(item.Value, &jsonEscaped)
        if err != nil {
            log.Fatalf("Error deserialazing the escaped JSON: %v", err)
        }
        // Parse the JSON from Memcached
        var incidentData map[string]interface{}
        err = json.Unmarshal([]byte(jsonEscaped), &incidentData)
        if err != nil {
            log.Fatalf("Error deserializing the JSON: %v", err)
        }

        // Add auth_token to the payload
        incidentData["auth_token"] = config.AuthToken

        // Call the Rails API to create the incident
        created, err := createIncident(config.ApiEndpoint, incidentData, config.InsecureSkipVerify)
        if err != nil {
          log.Printf("Error creating incident for key %s: %v", key, err)
          continue
        }

        if created {
          // Delete the key from Memcached if the incident was created successfully
          err = mc.Delete(key)
          if err != nil {
            log.Printf("Error deleting key %s: %v", key, err)
          } else {
            log.Printf("Successfully deleted key %s after creating incident", key)
          }
        }
      }
    }

    // Sleep for the configured interval
    log.Printf("Sleeping for %d seconds before next check...", config.LoopInterval)
    time.Sleep(time.Duration(config.LoopInterval) * time.Second)
  }
}

// getAllKeysFromMemcached retrieves all keys from Memcached using a direct TCP connection
func getAllKeysFromMemcached(memcachedServer string) ([]string, error) {
  conn, err := net.Dial("tcp", memcachedServer)
  if err != nil {
    return nil, fmt.Errorf("failed to connect to memcached: %v", err)
  }
  defer conn.Close()

  // Get the list of slabs
  fmt.Fprintf(conn, "stats items\n")
  scanner := bufio.NewScanner(conn)
  slabs := make(map[int]int)
  for scanner.Scan() {
    line := scanner.Text()
    if strings.HasPrefix(line, "STAT items:") {
      var slabID, numberOfItems int
      fmt.Sscanf(line, "STAT items:%d:number %d", &slabID, &numberOfItems)
      slabs[slabID] = numberOfItems
    } else if strings.HasPrefix(line, "END") {
      break
    }
  }

  if err := scanner.Err(); err != nil {
    return nil, fmt.Errorf("error reading slabs: %v", err)
  }

  // Get keys from each slab
  var keys []string
  for slabID := range slabs {
    fmt.Fprintf(conn, "stats cachedump %d 0\n", slabID)
    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
      line := scanner.Text()
      if strings.HasPrefix(line, "ITEM") {
        var key string
        fmt.Sscanf(line, "ITEM %s", &key)
        keys = append(keys, key)
      } else if strings.HasPrefix(line, "END") {
        break
      }
    }

    if err := scanner.Err(); err != nil {
      return nil, fmt.Errorf("error reading keys from slab %d: %v", slabID, err)
    }
  }

  return keys, nil
}

// createIncident sends a request to the Rails API to create an incident
func createIncident(apiEndpoint string, incidentData map[string]interface{}, insecureSkipVerify bool) (bool, error) {
  client := resty.New()
  // Configure TLS based on the parameter
  client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: insecureSkipVerify})

  // Send the request to create the incident
  resp, err := client.R().
    SetHeader("Content-Type", "application/json").
    SetBody(incidentData).
    Post(apiEndpoint)

  if err != nil {
    return false, err
  }

  // Check for success response
  if resp.StatusCode() != 201 {
    var errorResponse map[string]interface{}
    if err := json.Unmarshal(resp.Body(), &errorResponse); err != nil {
      return false, fmt.Errorf("failed to create incident, status code: %d", resp.StatusCode())
    }
    return false, fmt.Errorf("failed to create incident: %v", errorResponse["errors"])
  }

  log.Printf("Incident created successfully with data: %v", incidentData)
  return true, nil
}
