package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
)

const (
	// IPStackMethod to use
	IPStackMethod = "GET"
)

// GeoLocationResponse received from the IP Stack API
type GeoLocationResponse struct {
	IP            string             `json:"ip"`
	Type          string             `json:"type"`
	ContinentCode string             `json:"continent_code"`
	ContinentName string             `json:"continent_name"`
	CountryCode   string             `json:"country_code"`
	CountryName   string             `json:"country_name"`
	RegionCode    string             `json:"region_code"`
	RegionName    string             `json:"region_name"`
	City          string             `json:"city"`
	Zip           string             `json:"zip"`
	Latitude      float64            `json:"latitude"`
	Longitude     float64            `json:"longitude"`
	Location      GeoLocationCountry `json:"location"`
}

// GeoLocationLanguage as part of the data from the IP Stack API
type GeoLocationLanguage map[string]string

// GeoLocationCountry as part of the data from the IP Stack API
type GeoLocationCountry struct {
	GeonameID               uint                  `json:"geoname_id"`
	Capital                 string                `json:"capital"`
	Languages               []GeoLocationLanguage `json:"languages"`
	CountryFlag             string                `json:"country_flag"`
	CountryFlagEmoji        string                `json:"country_flag_emoji"`
	CountryFlagEmojiUnicode string                `json:"country_flag_emoji_unicode"`
	CallingCode             string                `json:"calling_code"`
	IsEU                    bool                  `json:"is_eu"`
}

// Helper to convert from received JSON structure to the data we want to store
// FIXME use cache for this to avoid too much I/O
func geolocationFromJSONData(data GeoLocationResponse) GeoLocationIPAddress {
	return GeoLocationIPAddress{
		IPAddress:     data.IP,
		Alias:         "",
		Type:          data.Type,
		ContinentCode: data.ContinentCode,
		ContinentName: data.ContinentName,
		CountryCode:   data.CountryCode,
		CountryName:   data.CountryName,
		RegionCode:    data.RegionCode,
		RegionName:    data.RegionName,
		City:          data.City,
		Zip:           data.Zip,
		Latitude:      data.Latitude,
		Longitude:     data.Longitude,
		EmojiFlag:     data.Location.CountryFlagEmoji,
	}
}

// If IP Address is not already stored, request the API and save it
func geoLocationCheckByIPAddress(ipaddress string) error {
	// IP Address geo location, if IP is public and geolocation is enabled
	if isPublicIP(net.ParseIP(ipaddress)) && geolocConfig.Maps {
		// Check if data is already mapped
		// FIXME check how old is the data, and maybe refresh if older than some time
		if !checkGeoLocationIPAddress(ipaddress) {
			// Retrieve new data
			newLoc, err := getIPStackData(ipaddress, geolocConfig.IPStackCfg)
			if err != nil {
				return fmt.Errorf("getIPStackData %v", err)
			}
			// Create entry in geo location table
			if err := newGeoLocationIPAddress(newLoc); err != nil {
				return fmt.Errorf("newGeoLocationIPAddress %v", err)
			}
		}
	}
	return nil
}

// Insert new entry for the geo location of an IP Address
func newGeoLocationIPAddress(geoloc GeoLocationIPAddress) error {
	if db.NewRecord(geoloc) {
		if err := db.Create(&geoloc).Error; err != nil {
			return fmt.Errorf("Create newGeoLocationIPAddress %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Check if IP Address is already mapped for Geo Location
func checkGeoLocationIPAddress(ipaddress string) bool {
	var results int
	db.Model(&GeoLocationIPAddress{}).Where("ip_address = ?", ipaddress).Count(&results)
	return (results > 0)
}

// Retrieve geo location data by IP Address
func getGeoLocationIPAddress(ipaddress string) (GeoLocationIPAddress, error) {
	var geoloc GeoLocationIPAddress
	if err := db.Where("ip_address = ?", ipaddress).Order("updated_at").First(&geoloc).Error; err != nil {
		return geoloc, err
	}
	return geoloc, nil
}

// Retrieve Geo Location data for an IP Address
func getIPStackData(ipaddress string, configData GeoLocationConfigurationData) (GeoLocationIPAddress, error) {
	// Prepare URL joining base URL with path
	_url, _ := url.Parse(configData["api"])
	_url.Path = path.Join(_url.Path, ipaddress)
	// Add query parameters
	queryString := _url.Query()
	queryString.Set("access_key", configData["apikey"])
	// Add query to URL
	_url.RawQuery = queryString.Encode()
	// Send log with a GET to the IP Stack API URL
	if tlsConfig.DebugHTTP {
		log.Printf("Request IP Stack API for %s", ipaddress)
	}
	resp, body, err := sendRequest(true, IPStackMethod, _url.String(), nil, map[string]string{})
	if err != nil {
		log.Printf("Error sending request %s", err)
	}
	if tlsConfig.DebugHTTP {
		log.Printf("IP Stack: HTTP %d %s", resp, body)
	}
	var jsonResponse GeoLocationResponse
	// Parse response JSON
	if resp == http.StatusOK {
		err := json.Unmarshal(body, &jsonResponse)
		if err != nil {
			log.Printf("error parsing JSON %s %v", string(body), err)
		}
	}
	// Convert returned JSON data with what we want to store
	return geolocationFromJSONData(jsonResponse), nil
}
