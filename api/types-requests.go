package main

// DistributedQueryRequest to receive query requests
type DistributedQueryRequest struct {
	Environments []string `json:"environment_list"`
	Platforms    []string `json:"platform_list"`
	UUIDs        []string `json:"uuid_list"`
	Hosts        []string `json:"host_list"`
	Query        string   `json:"query"`
}

// ApiErrorResponse to be returned to API requests with the error message
type ApiErrorResponse struct {
	Error string `json:"error"`
}

// ApiQueriesResponse to be returned to API requests for queries
type ApiQueriesResponse struct {
	Name string `json:"query_name"`
}
