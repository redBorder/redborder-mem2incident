package main

import (
  "bufio"
  "crypto/tls"
  "encoding/json"
  "flag"
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
  MemcachedServers   []string `yaml:"memcached_servers"`
  ApiEndpoint        string   `yaml:"api_endpoint"`
  LoopInterval       int      `yaml:"loop_interval"`        // Interval in seconds
  InsecureSkipVerify bool     `yaml:"insecure_skip_verify"` // Ignore TLS verification
  AuthToken          string   `yaml:"auth_token"`           // Authentication token
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

func main() {
  // Check if the program was called with the "version" argument
  if len(os.Args) > 1 && os.Args[1] == "version" {
    fmt.Printf("redborder-mem2incident version %s\n", version)
    return
  }

  // Define a flag for the configuration file
  configFile := flag.String("c", "config.yml", "configuration file")
  flag.Parse()

  // Read the configuration
  config, err := readConfig(*configFile)
  if (err != nil) {
    log.Fatalf("Error reading config: %v", err)
  }

  // Create a new Memcached client with multiple servers
  mc := memcache.New(config.MemcachedServers...)

  // Infinite loop to keep the service running
  for {
    // Get all keys from all Memcached servers
    var allKeys []string
    for _, server := range config.MemcachedServers {
      keys, err := getAllKeysFromMemcached(server)
      if (err != nil) {
        log.Printf("Error getting keys from server %s: %v", server, err)
      } else {
        allKeys = append(allKeys, keys...)
      }
    }

    for _, key := range allKeys {
      // Check if the key matches the pattern to create an incident
      if match, _ := regexp.MatchString(`^rbincident(:[a-fA-F0-9\-]+)?:incident:([a-fA-F0-9\-]+)$`, key); match {
        log.Printf("Getting key %s", key)

        // Get the value from Memcached
        item, err := mc.Get(key)

        if err != nil {
          if err == memcache.ErrCacheMiss {
            // If cache miss check all servers for the key
            for _, server := range config.MemcachedServers {
              mcSingle := memcache.New(server)
              item, err = mcSingle.Get(key)
              if err == nil {
                log.Printf("Key %s found on server %s", key, server)
                break
              } else if err != memcache.ErrCacheMiss {
                log.Printf("Error getting key %s from server %s: %v", key, server, err)
              }
            }
          }

          if err != nil {
            log.Printf("Key %s not found on any server: %v", key, err)
            continue
          }
        }

        // Deserialize escaped JSON
        var jsonEscaped string
        err = json.Unmarshal(item.Value, &jsonEscaped)
        if err != nil {
          log.Fatalf("Error deserializing the escaped JSON: %v", err)
        }

        // Parse the JSON from Memcached
        var incidentData map[string]interface{}
        err = json.Unmarshal([]byte(jsonEscaped), &incidentData)
        if err != nil {
          log.Fatalf("Error deserializing the JSON: %v", err)
        }

				// Verifies and assigns the 'domain' field in incidentData based on the value of 'domain'
				if domainValue, ok := incidentData["domain"]; ok { // Checks if 'domain' exists in the incidentData map
						domainStr, isString := domainValue.(string) // Tries to cast the value of 'domain' to a string

						if isString && len(domainStr) > 0 { // If 'domain' is a valid string and not empty
								log.Printf("Assigned sensor_id: %s", domainStr)
								incidentData["domain"] = domainStr // Assigns the value of 'domain' to the 'domain' field
						} else {
								// If 'domain' exists but is empty or not a valid string
								log.Printf("The domain field is empty or not a string, using default value")
								incidentData["domain"] = "" // Assigns an empty string as the default value
						}
				} else {
						// If the 'domain' field does not exist in incidentData
						log.Printf("The domain field is not present in the incident data, using default value")
						incidentData["domain"] = "" // Assigns an empty string as the default value
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
            if err == memcache.ErrCacheMiss {
              // If cache miss, check all servers for the key
              for _, server := range config.MemcachedServers {
                mcSingle := memcache.New(server)                
                err = mcSingle.Delete(key)
                if err == nil {
                  log.Printf("Successfully deleted key %s after creating incident", key)
                  break
                } else if err != memcache.ErrCacheMiss {
                  log.Printf("Error getting key %s from server %s: %v", key, server, err)
                }
              }
            }
            if err != nil {
              log.Printf("Error deleting key %s: %v", key, err)
              continue
            }
          } else {
            log.Printf("Successfully deleted key %s after creating incident", key)
          }
        }
      }

      // Check if the key matches the pattern to link incidents
      if match, _ := regexp.MatchString(`^rbincident:relation:([a-fA-F0-9\-]+)$`, key); match {
        log.Printf("Getting key to link incident %s", key)
	      
        // Get the value from Memcached
        item, err := mc.Get(key)

        if err != nil {
          if err == memcache.ErrCacheMiss {
            // If cache miss check all servers for the key
            for _, server := range config.MemcachedServers {
              mcSingle := memcache.New(server)
              item, err = mcSingle.Get(key)
              if err == nil {
                log.Printf("Key to link incident %s found on server %s", key, server)
                break
              } else if err != memcache.ErrCacheMiss {
                log.Printf("Error getting key to link incident %s from server %s: %v", key, server, err)
              }
            }
          }

          if err != nil {
            log.Printf("Key to link incident %s not found on any server: %v", key, err)
            continue
          }
        }

        parentUUID := strings.Split(key, ":")[2]
        childUUID := string(item.Value)

        // Call the Rails API to link the incident
        created, err := linkIncidents(config.ApiEndpoint, parentUUID, childUUID, config.AuthToken, config.InsecureSkipVerify)
        if err != nil {
          log.Printf("Error linking incident for key %s: %v", key, err)
          continue
        }

        if created {
          // Delete the key from Memcached if the incident was created successfully
          err = mc.Delete(key)

          if err != nil {
            if err == memcache.ErrCacheMiss {
              // If cache miss, check all servers for the key
              for _, server := range config.MemcachedServers {
                mcSingle := memcache.New(server)                
                err = mcSingle.Delete(key)
                if err == nil {
                  log.Printf("Successfully deleted key %s after linking incident", key)
                  break
                } else if err != memcache.ErrCacheMiss {
                  log.Printf("Error getting key to link incident %s from server %s: %v", key, server, err)
                }
              }
            }
            if err != nil {
              log.Printf("Error deleting key to link incident %s: %v", key, err)
              continue
            }
          } else {
            log.Printf("Successfully deleted key %s after linking incident", key)
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

// linkIncidents sends a request to the Rails API to link incidents
func linkIncidents(apiEndpoint string, parentUUID string, childUUID string, authToken string, insecureSkipVerify bool) (bool, error) {
	client := resty.New()
	// Configure TLS based on the parameter
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: insecureSkipVerify})

        // Sanitize the UUIDs by removing any surrounding quotation marks
	parentUUID = strings.Trim(parentUUID, "\"")
	childUUID = strings.Trim(childUUID, "\"")

	linkData := map[string]string{
		"parent_incident_uuid": parentUUID,
		"child_incident_uuid":  childUUID,
		"auth_token":           authToken,
	}

	// Send the request to link the incidents
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(linkData).
		Post(apiEndpoint + "/link")

	if err != nil {
		return false, err
	}

	// Check for success response
	if resp.StatusCode() != 201 {
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(resp.Body(), &errorResponse); err != nil {
			return false, fmt.Errorf("failed to link incidents, status code: %d", resp.StatusCode())
		}
		return false, fmt.Errorf("failed to link incidents: %v", errorResponse["errors"])
	}

	// If everything is successful, return true and nil for error
	log.Printf("Incidents linked successfully: %s -> %s", parentUUID, childUUID)
	return true, nil
}
