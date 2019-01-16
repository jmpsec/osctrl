package main

import (
	"encoding/json"
	"log"
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
	if adminConfig.DebugHTTP {
		log.Printf("Request IP Stack API for %s", ipaddress)
	}
	resp, body, err := sendRequest(true, IPStackMethod, _url.String(), nil, map[string]string{})
	if err != nil {
		log.Printf("Error sending request %s", err)
	}
	if adminConfig.DebugHTTP {
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
