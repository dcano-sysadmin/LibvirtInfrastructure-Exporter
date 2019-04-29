package main

import (
	"net/http"
	"github.com/sirupsen/logrus"
	"strconv"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"os/exec"
	"os"
	"bufio"
	"crypto/tls"
)

type MV struct {
	hostname string
	ip string
	status bool
}

var (
	log	=	logrus.New()
	contextLogger = log.WithFields(logrus.Fields{})
	ENVBLACKLIST = []string{"bacula"}
)

////////////////////////////////////////
///////////// METRICS //////////////////
////////////////////////////////////////
func getMetrics() (string) {
	salida := `# HELP LibvirtInfraestructure-Exporter
`
	// Environments
	for _,s := range environments() {
		salida +=`libvirt_infraestructure{environment="`+ s+`"} 1
`
	}
	// Interfaces
	for _,s := range environments() {
		exists_interface := false
		for _,t := range localTapAddressesUp() {
			if ("tap_"+s == t) {
				exists_interface = true
			}
		}
		if (exists_interface) {
			salida +=`libvirt_infraestructure_interface{environment="`+ s+`"} 1
`
		} else {
			salida +=`libvirt_infraestructure_interface{environment="`+ s+`"} 0
`

		}
	}
	// DHCP
	for _,s := range environments() {
		dhcp_running := false
		for _,p := range getLocalProccess() {
			if (strings.Contains(p,"/usr/sbin/dhcpd") && strings.Contains(p,s)) {
				dhcp_running = true
			} 
		}
		if (dhcp_running) {
			salida +=`libvirt_infraestructure_dhcp{environment="`+ s+`"} 1
`
		} else {
			salida +=`libvirt_infraestructure_dhcp{environment="`+ s+`"} 0
`				
		}
	}
	// Ubridge
	for _,s := range environments() {
		ubridge_running := false
		for _,p := range getLocalProccess() {
			if (strings.Contains(p,"/usr/sbin/ubridge") && strings.Contains(p,s)) {
				ubridge_running = true
			} 
		}
		if (ubridge_running) {
			salida +=`libvirt_infraestructure_ubridge{environment="`+ s+`"} 1
`
		} else {
			salida +=`libvirt_infraestructure_ubridge{environment="`+ s+`"} 0
`				
		}
	}
	// DNS
	dns_running := false
	for _,p := range getLocalProccess() {
		if (strings.Contains(p,"/usr/sbin/named")) {
			dns_running = true
		} 
	}
	if (dns_running) {
		salida +=`libvirt_infraestructure_dns{} 1
`
	} else {
		salida +=`libvirt_infraestructure_dns{} 0
`				
	}
	// Virtual Machines Status
	for _,s := range environments() {
		for _,m := range statusMachines(s) {
			if (m.status) {
			salida +=`libvirt_infraestructure_vm_status{environment="`+ s+`",vm="`+m.hostname+`",ip="`+m.ip+`"} 1
`
			} else {
			salida +=`libvirt_infraestructure_vm_status{environment="`+ s+`",vm="`+m.hostname+`",ip="`+m.ip+`"} 0
`			
			}
		} 
	}
	// Environments HTTP Status
	for _,s := range environments() {
		if (getHTTPCodeEnvironment("https://bootstrap."+s+".hetzner.stratio.com")) {
		salida +=`environment_http_status{environment="`+ s+`"} 1
`
		} else {
		salida +=`environment_http_status{environment="`+ s+`"} 0
`
		}
	} 
	return salida
}

////////////////////////////////////////
//////////// AUX FUNC //////////////////
////////////////////////////////////////

func statusMachines(env string) ([]MV) { 				// Status machines of one environment
	var mvs []string
	var machines []MV
    file, err := os.Open("/opt/"+env+"/dhcpd.conf")
    if err != nil {
    	fmt.Println(err)
    	file.Close()
    	return machines
        //log.Fatal(err)
    }

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
    	line := string(scanner.Text())
		if (strings.Contains(line," fixed-address ")) {
			testArray := strings.Split(line," ")
			for _,n := range testArray {
				if ( n!= "" && n!= "	" && n!= " " && n!= "{" && n!= "fixed-address" ) {
					mvs = append(mvs,strings.Replace(n, ";", "", -1))
					out, _ := exec.Command("ping", strings.Replace(n, ";", "", -1), "-c 1", "-i 0.1","-W 1").Output()
					if strings.Contains(string(out), "100% packet loss") {
						mvs = append(mvs,"false")
					} else {
						mvs = append(mvs,"true")
					}
				}
			}
		}
		if (strings.Contains(line," host ")) {
			testArray := strings.Split(line," ")
			for _,n := range testArray {
				if ( n!= "" && n!= "	" && n!= " " && n!= "{" && n!= "host" ) {
					mvs = append(mvs,n)	
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	file.Close()

	for i:=0; i<=len(mvs); i +=3 {
		if (i<len(mvs)) {
			result,_ := strconv.ParseBool(mvs[i+2])
			mach := MV{
				hostname: mvs[i],
				ip: mvs[i+1],
				status: result,
			}
			machines = append(machines,mach)
		}		
	}
	return machines
}

func getHTTPCodeEnvironment(url string) (bool) {
	var status bool
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println(err)
		status=false
		return status
	}
	defer resp.Body.Close() 

	//fmt.Println("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))
	
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		//fmt.Println("OK - HTTP 2XX response ")
		status=true
	} else {
		//fmt.Println("ERROR - Not HTTP 2XX response")
		status=false
	}

	return status
}

func localTapAddressesUp() ([]string) {				// Check status tap interfaces
	var tap_interfaces []string
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return tap_interfaces
	}
	for _, i := range ifaces {
		if err != nil {
			fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
			continue
		}
		if(strings.Contains(i.Name,"tap_")) {
			tap_interfaces = append(tap_interfaces,i.Name)
		}
	}
	return tap_interfaces
}

func getLocalProccess() ([]string) {				// Check if one proccess is running
	var proccess []string
	out, _ := exec.Command("ps", "-aux").Output()
	testArray := strings.Split(string(out),"\n")
	for _,l := range testArray {
		proccess = append (proccess,l)
	}
	return proccess
}

func environments() ([]string) {					// Get environments listing opt directories
	var env []string
	files, err := ioutil.ReadDir("/opt/")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if ( !isValueInList(f.Name(), ENVBLACKLIST) ) {
			env = append(env,f.Name())
		}
	}
	return env
}

func isValueInList(value string, list []string) bool {
    for _, v := range list {
        if v == value {
            return true
        }
    }
    return false
}

////////////////////////////////////////
//////////// MAIN //////////////////////
////////////////////////////////////////
func main() {
	// WEB SERVER
	contextLogger.Info("Starting LibvirtInfraestructure-Exporter")
	
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(getMetrics()))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
						<head><title>LibvirtInfraestructure Exporter</title></head>
						<body>
							<h1>LibvirtInfraestructure Prometheus Metrics Exporter</h1>
							<p>For more information, visit <a href=https://github.com/dcano-sysadmin/LibvirtInfraestructure-Exporter>GitHub</a></p>
							<p><a href='/metrics'>Metrics</a></p>
						</body>
						</html>
					`))
	})
	log.Fatal(http.ListenAndServe(":9171", nil))

}