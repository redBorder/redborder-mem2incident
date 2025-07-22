package main

import (
  "context"
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

  "github.com/redis/go-redis/v9"
  "github.com/go-resty/resty/v2"
  "gopkg.in/yaml.v2"
)

const version = "2.0.0"

// Config structure to hold the configuration
type Config struct {
  RedisHosts         []string `yaml:"redis_hosts"`
  RedisPort          int      `yaml:"redis_port"`
  RedisPassword      string   `yaml:"redis_password"`
  RedisDB            int      `yaml:"redis_db"`
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

  ctx := context.Background()
  rdb := redis.NewClient(&redis.Options{
    Addr:     fmt.Sprintf("%s:%d", config.RedisHosts[0], config.RedisPort),
    Password: config.RedisPassword,
    DB:       config.RedisDB,
  })

  if err := rdb.Ping(ctx).Err(); err != nil {
    log.Fatalf("Error connecting to Redis: %v", err)
  }

  for {
    allKeys, err := getAllKeysFromRedis(ctx, rdb, "rbincident:*")
    if err != nil {
      log.Printf("Error fetching keys: %v", err)
      time.Sleep(time.Duration(config.LoopInterval) * time.Second)
      continue
    }

    for _, key := range allKeys {
      // Check if the key matches the pattern to create an incident
      if match, _ := regexp.MatchString(`^rbincident(:[a-fA-F0-9\-]+)?:incident:([a-fA-F0-9\-]+)$`, key); match {
        log.Printf("Getting key %s", key)
        val, err := rdb.Get(ctx, key).Result()
        if err == redis.Nil {
          continue
        } else if err != nil {
          log.Printf("Error getting key %s: %v", key, err)
          continue
        }

        var incidentData map[string]interface{}
        if err := json.Unmarshal([]byte(val), &incidentData); err != nil {
          log.Printf("Error deserializing JSON: %v", err)
          continue
        }

        incidentData["auth_token"] = config.AuthToken
        created, err := createIncident(config.ApiEndpoint, incidentData, config.InsecureSkipVerify)
        if err != nil {
          log.Printf("Error creating incident: %v", err)
          continue
        }

        if created {
          if err := rdb.Del(ctx, key).Err(); err != nil {
            log.Printf("Error deleting key %s: %v", key, err)
          } else {
            log.Printf("Deleted key %s", key)
          }
        }
      }

      // Check if the key matches the pattern to link incidents
      if match, _ := regexp.MatchString(`^rbincident:relation:([a-fA-F0-9\-]+)$`, key); match {
        log.Printf("Getting key to link incident %s", key)
        val, err := rdb.Get(ctx, key).Result()
        if err == redis.Nil {
          continue
        } else if err != nil {
          log.Printf("Error getting key: %v", err)
          continue
        }

        parentUUID := strings.Split(key, ":")[2]
        childUUID := strings.Trim(val, "\"")

        created, err := linkIncidents(config.ApiEndpoint, parentUUID, childUUID, config.AuthToken, config.InsecureSkipVerify)
        if err != nil {
          log.Printf("Error linking incidents: %v", err)
          continue
        }

        if created {
          if err := rdb.Del(ctx, key).Err(); err != nil {
            log.Printf("Error deleting key: %v", err)
          } else {
            log.Printf("Deleted key %s after linking", key)
          }
        }
      }
    }

    // Sleep for the configured interval
    log.Printf("Sleeping for %d seconds before next check...", config.LoopInterval)
    time.Sleep(time.Duration(config.LoopInterval) * time.Second)
  }
}

// getAllKeysFromRedis retrieves all keys from Redis that match the given pattern
func getAllKeysFromRedis(ctx context.Context, rdb *redis.Client, pattern string) ([]string, error) {
  var cursor uint64
  var keys []string
  
  for {
    k, c, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
    if err != nil {
      return nil, err
    }
    keys = append(keys, k...)
    cursor = c
    if cursor == 0 {
      break
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
