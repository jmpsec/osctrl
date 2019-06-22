package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/javuto/osctrl/pkg/environments"
	"github.com/javuto/osctrl/pkg/queries"
	"github.com/javuto/osctrl/pkg/settings"

	"github.com/gorilla/mux"
)

// Handler for login page for POST requests
func loginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	responseMessage := "OK"
	responseCode := http.StatusOK
	var l LoginRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check credentials
		if access, user := adminUsers.CheckLoginCredentials(l.Username, l.Password); access {
			err = sessionsmgr.Save(r, w, user)
			if err != nil {
				responseMessage = "session error"
				responseCode = http.StatusForbidden
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v)", responseMessage, err)
				}
			}
		} else {
			responseMessage = "invalid credentials"
			responseCode = http.StatusForbidden
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Login response sent")
	}
}

// Handle POST requests to logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	var l LogoutRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], l.CSRFToken) {
			// Destroy existing session
			err := sessionsmgr.Destroy(r)
			if err != nil {
				log.Printf("error destroying session [ %v ]", err)
				http.Error(w, "Session Error", http.StatusInternalServerError)
				return
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Logout response sent")
	}
}

// Handler for POST requests to run queries
func queryRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "The query was created successfully"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	var q DistributedQueryRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&q)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
		goto response
	}
	// Check CSRF Token
	if checkCSRFToken(ctx["csrftoken"], q.CSRFToken) {
		// FIXME check validity of query
		// Query can not be empty
		if q.Query == "" {
			responseMessage = "query can not be empty"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
			goto response
		}
		// Prepare and create new query
		queryName := "query_" + generateQueryName()
		newQuery := queries.DistributedQuery{
			Query:      q.Query,
			Name:       queryName,
			Creator:    ctx["user"],
			Executions: 0,
			Active:     true,
			Completed:  false,
			Deleted:    false,
			Repeat:     0,
			Type:       queries.StandardQueryType,
		}
		if err := queriesmgr.Create(newQuery); err != nil {
			responseMessage = "error creating query"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
			goto response
		}
		// Create environment target
		if (q.Environment != "") && envs.Exists(q.Environment) {
			if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetEnvironment, q.Environment); err != nil {
				responseMessage = "error creating query environment target"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
				goto response
			}
		}
		// Create platform target
		if (q.Platform != "") && checkValidPlatform(q.Platform) {
			if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetPlatform, q.Platform); err != nil {
				responseMessage = "error creating query platform target"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
				goto response
			}
		}
		// Create UUIDs target
		// FIXME verify UUIDs
		if len(q.UUIDs) > 0 {
			for _, u := range q.UUIDs {
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetUUID, u); err != nil {
					responseMessage = "error creating query UUID target"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
					goto response
				}
			}
		}
		// Create hostnames target
		// FIXME verify localnames
		if len(q.Hosts) > 0 {
			for _, h := range q.Hosts {
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetLocalname, h); err != nil {
					responseMessage = "error creating query hostname target"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
					goto response
				}
			}
		}
	} else {
		responseMessage = "invalid CSRF token"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	}
response:
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run response sent")
	}
}

// Handler for POST requests to see completed queries
func queryActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var q DistributedQueryActionRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&q)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], q.CSRFToken) {
			switch q.Action {
			case "delete":
				for _, n := range q.Names {
					err := queriesmgr.Delete(n)
					if err != nil {
						responseMessage = "error deleting query"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					}
				}
			case "complete":
				for _, n := range q.Names {
					err := queriesmgr.Complete(n)
					if err != nil {
						responseMessage = "error completing query"
						responseCode = http.StatusInternalServerError
						log.Printf("%s %v", responseMessage, err)
					}
				}
			case "activate":
				for _, n := range q.Names {
					err := queriesmgr.Activate(n)
					if err != nil {
						responseMessage = "error activating query"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					}
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run response sent")
	}
}

// Handler POST requests for saving configuration
func confPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "Configuration saved successfully"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment and verify
	environmentVar, ok := vars["environment"]
	if !ok || !envs.Exists(environmentVar) {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error getting environment")
		}
		return
	}
	// Verify environment
	if !envs.Exists(environmentVar) {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error unknown environment (%s)", environmentVar)
		}
		return
	}
	var c ConfigurationRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], c.CSRFToken) {
			configuration, err := base64.StdEncoding.DecodeString(c.ConfigurationB64)
			if err != nil {
				responseMessage = "error decoding configuration"
				responseCode = http.StatusInternalServerError
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
			} else {
				err = envs.UpdateConfiguration(environmentVar, string(configuration))
				if err != nil {
					responseMessage = "error saving configuration"
					responseCode = http.StatusInternalServerError
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Configuration response sent")
	}
}

// Handler POST requests for saving intervals
func intervalsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "Intervals updated successfully"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	environmentVar, ok := vars["environment"]
	if !ok {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error getting environment")
		}
		return
	}
	// Verify environment
	if !envs.Exists(environmentVar) {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error unknown environment (%s)", environmentVar)
		}
		return
	}
	var c IntervalsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], c.CSRFToken) {
			err = envs.UpdateIntervals(environmentVar, c.ConfigInterval, c.LogInterval, c.QueryInterval)
			if err != nil {
				responseMessage = "error updating intervals"
				responseCode = http.StatusInternalServerError
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Intervals response sent")
	}
}

// Handler POST requests for expiring enroll links
func expirationPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	environmentVar, ok := vars["environment"]
	if !ok {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error getting environment")
		}
		return
	}
	// Verify environment
	if !envs.Exists(environmentVar) {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error unknown environment (%s)", environmentVar)
		}
		return
	}
	var e ExpirationRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&e)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], e.CSRFToken) {
			switch e.Type {
			case "enroll":
				switch e.Action {
				case "expire":
					err = envs.ExpireEnroll(environmentVar)
					if err != nil {
						responseMessage = "error expiring enroll"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					}
				case "extend":
					err = envs.RotateEnrollPath(environmentVar)
					if err != nil {
						responseMessage = "error extending enroll"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					}
				}
			case "remove":
				switch e.Action {
				case "expire":
					err = envs.ExpireRemove(environmentVar)
					if err != nil {
						responseMessage = "error expiring enroll"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					}
				case "extend":
					err = envs.RotateRemove(environmentVar)
					if err != nil {
						responseMessage = "error extending enroll"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					}
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Expiration response sent")
	}
}

// Handler POST requests for multi node action
func nodeMultiActionHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var m NodeMultiActionRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], m.CSRFToken) {
			switch m.Action {
			case "delete":
				okCount := 0
				errCount := 0
				for _, u := range m.UUIDs {
					err := nodesmgr.ArchiveDeleteByUUID(u)
					if err != nil {
						errCount++
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: error deleting node %s %v", u, err)
						}
					} else {
						okCount++
					}
				}
				if errCount == 0 {
					responseMessage = fmt.Sprintf("%d Node(s) have been deleted successfully", okCount)
				} else {
					responseMessage = fmt.Sprintf("Error deleting %d node(s)", errCount)
					responseCode = http.StatusInternalServerError
				}
			case "archive":
				log.Printf("DebugService: archiving node")
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Multi-node action response sent")
	}
}

// Handler POST requests for single node action
func nodeActionHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error getting uuid")
		}
		return
	}
	var n NodeActionRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&n)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], n.CSRFToken) {
			switch n.Action {
			case "delete":
				err := nodesmgr.ArchiveDeleteByUUID(uuid)
				if err != nil {
					responseMessage = "error deleting node"
					responseCode = http.StatusInternalServerError
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
				} else {
					responseMessage = "Node has been deleted successfully"
				}
			case "archive":
				log.Printf("DebugService: archiving node")
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Node action response sent")
	}
}

// Handler for POST request for /environments
func envsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var c EnvironmentsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], c.CSRFToken) {
			switch c.Action {
			case "create":
				// FIXME verify fields
				if !envs.Exists(c.Name) {
					env := envs.Empty(c.Name, c.Hostname)
					env.Icon = c.Icon
					env.Type = c.Type
					if env.Configuration == "" {
						env.Configuration = environments.ReadExternalFile(emptyConfiguration)
					}
					err := envs.Create(env)
					if err != nil {
						responseMessage = "error creating environment"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					} else {
						responseMessage = " Environment created successfully"
					}
				}
			case "delete":
				if c.Name == settingsmgr.DefaultEnv(settings.ServiceAdmin) {
					responseMessage = "Not a good idea"
					responseCode = http.StatusInternalServerError
				} else {
					if envs.Exists(c.Name) {
						err := envs.Delete(c.Name)
						if err != nil {
							responseMessage = "error deleting environment"
							responseCode = http.StatusInternalServerError
							if settingsmgr.DebugService(settings.ServiceAdmin) {
								log.Printf("DebugService: %s %v", responseMessage, err)
							}
						} else {
							responseMessage = " Environment deleted successfully"
						}
					}
				}
			case "debug":
				// FIXME verify fields
				if envs.Exists(c.Name) {
					err := envs.ChangeDebugHTTP(c.Name, c.DebugHTTP)
					if err != nil {
						responseMessage = "error changing DebugHTTP"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					} else {
						responseMessage = "DebugHTTP changed successfully"
					}
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService:  Environments response sent")
	}
}

// Handler for POST request for /settings
func settingsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract service
	serviceVar, ok := vars["service"]
	if !ok {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error getting service")
		}
		return
	}
	// Verify service
	if serviceVar != settings.ServiceTLS && serviceVar != settings.ServiceAdmin {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error unknown service (%s)", serviceVar)
		}
		return
	}
	var s SettingsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&s)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], s.CSRFToken) {
			switch s.Action {
			case "add":
				// FIXME verify type
				var err error
				switch s.Type {
				case settings.TypeBoolean:
					err = settingsmgr.NewBooleanValue(serviceVar, s.Name, stringToBoolean(s.Value))
				case settings.TypeInteger:
					err = settingsmgr.NewIntegerValue(serviceVar, s.Name, stringToInteger(s.Value))
				case settings.TypeString:
					err = settingsmgr.NewStringValue(serviceVar, s.Name, s.Value)
				}
				if err != nil {
					responseMessage = "error adding setting"
					responseCode = http.StatusInternalServerError
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
				} else {
					responseMessage = "Setting added successfully"
				}
			case "change":
				// FIXME verify type
				var err error
				switch s.Type {
				case settings.TypeBoolean:
					err = settingsmgr.SetBoolean(s.Boolean, serviceVar, s.Name)
				case settings.TypeInteger:
					err = settingsmgr.SetInteger(stringToInteger(s.Value), serviceVar, s.Name)
				case settings.TypeString:
					err = settingsmgr.SetString(s.Value, serviceVar, s.Name)
				}
				if err != nil {
					responseMessage = "error changing setting"
					responseCode = http.StatusInternalServerError
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
				} else {
					responseMessage = "Setting changed successfully"
				}
			case "delete":
				var err error
				err = settingsmgr.DeleteValue(serviceVar, s.Name)
				if err != nil {
					responseMessage = "error deleting setting"
					responseCode = http.StatusInternalServerError
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
				} else {
					responseMessage = "Setting deleted successfully"
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Settings response sent")
	}
}

// Handler for POST request for /users
func usersPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var u UsersRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
	} else {
		// Check CSRF Token
		if checkCSRFToken(ctx["csrftoken"], u.CSRFToken) {
			switch u.Action {
			case "add":
				// FIXME password complexity?
				if adminUsers.Exists(u.Username) {
					responseMessage = "user already exists"
					responseCode = http.StatusInternalServerError
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
				} else {
					newUser, err := adminUsers.New(u.Username, u.Password, u.Fullname, u.Admin)
					if err != nil {
						responseMessage = "error with new user"
						responseCode = http.StatusInternalServerError
						if settingsmgr.DebugService(settings.ServiceAdmin) {
							log.Printf("DebugService: %s %v", responseMessage, err)
						}
					} else {
						if err = adminUsers.Create(newUser); err != nil {
							responseMessage = "error creating user"
							responseCode = http.StatusInternalServerError
							if settingsmgr.DebugService(settings.ServiceAdmin) {
								log.Printf("DebugService: %s %v", responseMessage, err)
							}
						}
						responseMessage = "User added successfully"
					}
				}
			case "remove":
				if u.Username == ctx["user"] {
					responseMessage = "Not a good idea"
					responseCode = http.StatusInternalServerError
				} else {
					if adminUsers.Exists(u.Username) {
						err = adminUsers.Delete(u.Username)
						if err != nil {
							responseMessage = "error removing user"
							responseCode = http.StatusInternalServerError
							if settingsmgr.DebugService(settings.ServiceAdmin) {
								log.Printf("DebugService: %s %v", responseMessage, err)
							}
						} else {
							responseMessage = "User removed"
						}
					}
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		responseMessage = "error formating response"
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		responseCode = http.StatusInternalServerError
		response = []byte(responseMessage)
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	_, _ = w.Write(response)
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users response sent")
	}
}
