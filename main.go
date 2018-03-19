package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ARGOeu/argo-messaging/brokers"
	"github.com/ARGOeu/argo-messaging/config"
	"github.com/ARGOeu/argo-messaging/push"
	"github.com/ARGOeu/argo-messaging/stores"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/handlers"
)

func main() {
	// create and load configuration object
	cfg := config.NewAPICfg("LOAD")

	// create the store
	store := stores.NewMongoStore(cfg.StoreHost, cfg.StoreDB)
	store.Initialize()

	// create and initialize broker based on configuration
	broker := brokers.NewKafkaBroker(cfg.GetZooList())
	defer broker.CloseConnections()

	sndr := push.NewHTTPSender(1)

	mgr := push.NewManager(broker, store, sndr)
	mgr.LoadPushSubs()
	mgr.StartAll()
	// create and initialize API routing object
	API := NewRouting(cfg, broker, store, mgr, defaultRoutes)

	//Configure TLS support only
	config := &tls.Config{
		MinVersion:               tls.VersionTLS10,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.VerifyClientCertIfGiven,
		ClientCAs:                load_CAs(&cfg.CAs),
	}

	// Initialize CORS specifics
	xReqWithConType := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type"})
	allowVerbs := handlers.AllowedMethods([]string{"OPTIONS", "POST", "GET", "PUT", "DELETE", "HEAD"})
	// Initialize server wth proper parameters
	server := &http.Server{Addr: ":" + strconv.Itoa(cfg.Port), Handler: handlers.CORS(xReqWithConType, allowVerbs)(API.Router), TLSConfig: config}

	// Web service binds to server. Requests served over HTTPS.
	err := server.ListenAndServeTLS(cfg.Cert, cfg.CertKey)
	if err != nil {
		log.Fatal("API", "\t", "ListenAndServe:", err)
	}
}

// load_CAs reads the root certificates from a directory within the filesystsem, and creates the trusted root CA chain
func load_CAs(dir *string) (roots *x509.CertPool) {
	log.Info("Building the root CA chain...")
	pattern := "*.pem"
	roots = x509.NewCertPool()
	err := filepath.Walk(*dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalf("Prevent panic by handling failure accessing a path %q: %v\n", *dir, err)
			return err
		}
		if ok, _ := filepath.Match(pattern, info.Name()); ok {
			//fmt.Print("\n" + filepath.Join(*dir, info.Name()))
			bytes, _ := ioutil.ReadFile(filepath.Join(*dir, info.Name()))
			//fmt.Print("\n")
			//fmt.Printf("%s", bytes)
			if ok = roots.AppendCertsFromPEM(bytes); !ok {
				return errors.New("Something went wrong while parsing certificate: " + filepath.Join(*dir, info.Name()))
			}
		}
		// if info.IsDir() {
		// 	log.Infof("Skipping a dir without errors: %+v \n", info.Name())
		// }
		return nil
	})

	if err != nil {
		log.Fatalf("error walking the path %q: %v\n", *dir, err)
	} else {
		log.Info("API", "\t", "All certificates parsed successfully.")
	}

	return

}
