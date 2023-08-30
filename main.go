package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"google.golang.org/protobuf/proto"
	// "github.com/golang/protobuf/proto" v1.4.3
	// "github.com/v2ray/v2ray-core/app/router" v4.23.2
	// "github.com/v2ray/v2ray-core/infra/conf" v4.23.2
	// "github.com/golang/protobuf/proto"
	// "github.com/xtls/xray-core/app/router"
	// "github.com/xtls/xray-core/infra/conf"
)

type vEntryType int32

const (
	vEntryTypeUnknown      vEntryType = 0
	vEntryTypeDomain       vEntryType = 1
	vEntryTypeRegex        vEntryType = 2
	vEntryTypeKeyword      vEntryType = 3
	vEntryTypeFull         vEntryType = 4
	vEntryTypeIP           vEntryType = 10
	vEntryTypeIPSubnetMask vEntryType = 11
	vEntryTypeInclude      vEntryType = 100
)

type vEntry struct {
	Type  vEntryType
	Value string
	Attrs []*router.Domain_Attribute
}

type vFileType int32

const (
	vFileTypeSite vFileType = 0
	vFileTypeIP   vFileType = 1
)

func fileType(filename string) vFileType {
	if strings.HasSuffix(filename, "site") {
		return vFileTypeSite
	}
	if strings.HasSuffix(filename, "ip") {
		return vFileTypeIP
	}
	return vFileTypeSite
}

type vList struct {
	Name  string
	Type  vFileType
	Entry []vEntry
}

type vParsedSiteList struct {
	Name      string
	Inclusion map[string]bool
	Entry     []vEntry
}

type vParsedIPList struct {
	Name      string
	Inclusion map[string]bool
	Entry     []vEntry
}

func (l *vParsedSiteList) toProto() (*router.GeoSite, error) {
	site := &router.GeoSite{
		CountryCode: l.Name,
	}
	for _, entry := range l.Entry {
		switch entry.Type {
		case vEntryTypeDomain:
			site.Domain = append(site.Domain, &router.Domain{
				Type:      router.Domain_Domain,
				Value:     entry.Value,
				Attribute: entry.Attrs,
			})
		case vEntryTypeRegex:
			site.Domain = append(site.Domain, &router.Domain{
				Type:      router.Domain_Regex,
				Value:     entry.Value,
				Attribute: entry.Attrs,
			})
		case vEntryTypeKeyword:
			site.Domain = append(site.Domain, &router.Domain{
				Type:      router.Domain_Plain,
				Value:     entry.Value,
				Attribute: entry.Attrs,
			})
		case vEntryTypeFull:
			site.Domain = append(site.Domain, &router.Domain{
				Type:      router.Domain_Full,
				Value:     entry.Value,
				Attribute: entry.Attrs,
			})
		default:
			return nil, errors.New("unknown domain type: " + string(l.Name))
		}
	}
	return site, nil
}

func ParseIP(s string) (*router.CIDR, error) {
	var addr, mask string
	i := strings.Index(s, "/")
	if i < 0 {
		addr = s
	} else {
		addr = s[:i]
		mask = s[i+1:]
	}
	ip := net.ParseAddress(addr)
	switch ip.Family() {
	case net.AddressFamilyIPv4:
		bits := uint32(32)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, errors.New("invalid network mask for router: " + mask)
			}
			bits = uint32(bits64)
		}
		if bits > 32 {
			return nil, errors.New("invalid network mask for router: bites > 32")
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	case net.AddressFamilyIPv6:
		bits := uint32(128)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, errors.New("invalid network mask for router: " + mask)
			}
			bits = uint32(bits64)
		}
		if bits > 128 {
			return nil, errors.New("invalid network mask for router: bites > 128")
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	default:
		return nil, errors.New("unsupported address for router: " + s)
	}
}

func (l *vParsedIPList) toProto() (*router.GeoIP, error) {
	ip := &router.GeoIP{
		CountryCode: l.Name,
	}
	for _, entry := range l.Entry {
		if entry.Type == vEntryTypeIP || entry.Type == vEntryTypeIPSubnetMask {
			cidr, err := ParseIP(entry.Value)
			if err != nil {
				continue
			}
			ip.Cidr = append(ip.Cidr, cidr)
		}
	}
	return ip, nil
}

func removeComment(line string) string {
	idx := strings.Index(line, "#")
	if idx == -1 {
		return line
	}
	return strings.TrimSpace(line[:idx])
}

func parseDomain(domain string, entry *vEntry) error {
	kv := strings.Split(domain, ":")
	entry.Type = vEntryTypeUnknown

	if len(kv) == 1 {
		entry.Type = vEntryTypeDomain
		entry.Value = strings.ToLower(kv[0])
		return nil
	}

	if len(kv) == 2 {
		switch strings.ToLower(kv[0]) {
		case "domain":
			entry.Type = vEntryTypeDomain
		case "regex":
			entry.Type = vEntryTypeRegex
		case "keyword":
			entry.Type = vEntryTypeKeyword
		case "full":
			entry.Type = vEntryTypeFull
		case "include":
			entry.Type = vEntryTypeInclude
		}
		entry.Value = strings.ToLower(kv[1])
		return nil
	}

	return errors.New("Invalid format: " + domain)
}

func parseIP(ip string, entry *vEntry) error {
	kv := strings.Split(ip, ":")

	entry.Type = vEntryTypeUnknown

	if len(kv) == 1 {
		entry.Type = vEntryTypeIP
		var ipString = strings.ToLower(kv[0])

		entry.Value = ipString
		return nil
	}

	if len(kv) == 2 {
		entry.Type = vEntryTypeInclude
		entry.Value = strings.ToLower(kv[1])
		return nil
	}
	return errors.New("Invalid format: " + ip)
}

func parseAttribute(attr string) (router.Domain_Attribute, error) {
	var attribute router.Domain_Attribute
	if len(attr) == 0 || attr[0] != '@' {
		return attribute, errors.New("invalid attribute: " + attr)
	}

	attr = attr[0:]
	parts := strings.Split(attr, "=")
	if len(parts) == 1 {
		attribute.Key = strings.ToLower(parts[0])
		attribute.TypedValue = &router.Domain_Attribute_BoolValue{BoolValue: true}
	} else {
		attribute.Key = strings.ToLower(parts[0])
		intValue, err := strconv.Atoi(parts[1])
		if err != nil {
			return attribute, errors.New("invalid attribute: " + attr + ": " + err.Error())
		}
		attribute.TypedValue = &router.Domain_Attribute_IntValue{IntValue: int64(intValue)}
	}
	return attribute, nil
}

func parseSiteEntry(line string) (vEntry, error) {
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")

	var entry vEntry
	if len(parts) == 0 {
		return entry, errors.New("empty entry")
	}

	if err := parseDomain(parts[0], &entry); err != nil {
		return entry, err
	}

	for i := 1; i < len(parts); i++ {
		attr, err := parseAttribute(parts[i])
		if err != nil {
			return entry, err
		}
		entry.Attrs = append(entry.Attrs, &attr)
	}

	return entry, nil
}

func parseIPEntry(line string) (vEntry, error) {
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")

	var entry vEntry
	if len(parts) == 0 {
		return entry, errors.New("empty entry")
	}

	if err := parseIP(parts[0], &entry); err != nil {
		return entry, err
	}

	return entry, nil
}

func getCurrentDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return strings.Replace(dir, "\\", "/", -1)
}

func detectPath(path string) (string, error) {
	_, err := os.Stat(path)
	if err == nil || os.IsExist(err) {
		return path, nil
	}

	err = errors.New("No file found in GOPATH")
	return "", err
}

func load(path string) (*vList, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	list := &vList{
		Name: strings.ToUpper(filepath.Base(path)),
		Type: fileType(filepath.Base(path)),
	}
	scanner := bufio.NewScanner(file)
	if list.Type == vFileTypeSite {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			line = removeComment(line)
			if len(line) == 0 {
				continue
			}
			entry, err := parseSiteEntry(line)
			if err != nil {
				return nil, err
			}
			list.Entry = append(list.Entry, entry)
		}
		return list, nil
	}
	if list.Type == vFileTypeIP {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			line = removeComment(line)
			if len(line) == 0 {
				continue
			}
			entry, err := parseIPEntry(line)
			if err != nil {
				return nil, err
			}
			list.Entry = append(list.Entry, entry)
		}
		return list, nil
	}
	return nil, nil
}

func parseSiteList(list *vList, ref map[string]*vList) (*vParsedSiteList, error) {
	pl := &vParsedSiteList{
		Name:      list.Name,
		Inclusion: make(map[string]bool),
	}
	entryList := list.Entry
	for {
		newEntryList := make([]vEntry, 0, len(entryList))
		hasInclude := false
		for _, entry := range entryList {
			if entry.Type == vEntryTypeInclude {
				if pl.Inclusion[entry.Value] {
					continue
				}
				refName := strings.ToUpper(entry.Value)
				pl.Inclusion[refName] = true
				r := ref[refName]
				if r == nil {
					return nil, errors.New(entry.Value + " not found.")
				}
				newEntryList = append(newEntryList, r.Entry...)
				hasInclude = true
			} else {
				newEntryList = append(newEntryList, entry)
			}
		}
		entryList = newEntryList
		if !hasInclude {
			break
		}
	}
	pl.Entry = entryList

	return pl, nil
}

func parseIPList(list *vList, ref map[string]*vList) (*vParsedIPList, error) {
	pl := &vParsedIPList{
		Name:      list.Name,
		Inclusion: make(map[string]bool),
	}
	entryList := list.Entry
	for {
		newEntryList := make([]vEntry, 0, len(entryList))
		hasInclude := false
		for _, entry := range entryList {
			if entry.Type == vEntryTypeInclude {
				if pl.Inclusion[entry.Value] {
					continue
				}
				refName := strings.ToUpper(entry.Value)
				pl.Inclusion[refName] = true
				r := ref[refName]
				if r == nil {
					return nil, errors.New(entry.Value + " not found.")
				}
				newEntryList = append(newEntryList, r.Entry...)
				hasInclude = true
			} else {
				newEntryList = append(newEntryList, entry)
			}
		}
		entryList = newEntryList
		if !hasInclude {
			break
		}
	}
	pl.Entry = entryList

	return pl, nil
}

var dataPath string

func init() {
	flag.StringVar(&dataPath, "dataPath", "./", "Data path is required.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of params:\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	sourceDir, err := detectPath(dataPath)
	if err != nil {
		fmt.Println("Failed: ", err)
		return
	}
	ref := make(map[string]*vList)
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		list, err := load(path)

		if err != nil {
			// return err
			return nil
		}
		ref[list.Name] = list
		return nil
	})
	if err != nil {
		fmt.Println("Failed: ", err)
		return
	}
	siteList := new(router.GeoSiteList)
	ipList := new(router.GeoIPList)
	siteMapList := make([]string, 0)
	ipMapList := make([]string, 0)
	yamlPACList := make([]string, 0)
	for _, list := range ref {
		if list.Type == vFileTypeSite {
			// Append Domain Map
			siteMapList = append(siteMapList, strings.ToLower(list.Name))

			// Append YAML PAC List
			yamlPACList = append(yamlPACList, "# Domain:"+strings.ToLower(list.Name))
			for _, v := range list.Entry {
				// - DOMAIN-SUFFIX,domain.com,Proxy
				yamlPACList = append(yamlPACList, "- DOMAIN-SUFFIX,"+v.Value+",Proxy")
			}
			psl, err := parseSiteList(list, ref)
			if err != nil {
				fmt.Println("Failed: ", err)
				return
			}
			site, err := psl.toProto()
			if err != nil {
				fmt.Println("Failed: ", err)
				return
			}
			siteList.Entry = append(siteList.Entry, site)
			continue
		}
		if list.Type == vFileTypeIP {
			// Append Domain Map
			ipMapList = append(ipMapList, strings.ToLower(list.Name))

			// Append YAML PAC List
			yamlPACList = append(yamlPACList, "# IP:"+strings.ToLower(list.Name))
			for _, v := range list.Entry {
				// - IP-CIDR,34.214.88.100/32, Proxy
				yamlPACList = append(yamlPACList, "- IP-CIDR,"+v.Value+"/32,Proxy")
			}
			pIPList, err := parseIPList(list, ref)
			if err != nil {
				fmt.Println("Failed: ", err)
				return
			}
			ips, err := pIPList.toProto()
			if err != nil {
				fmt.Println("Failed: ", err)
				return
			}
			ipList.Entry = append(ipList.Entry, ips)
			continue
		}
	}

	// Site List
	protoBytes, err := proto.Marshal(siteList)
	if err != nil {
		fmt.Println("Failed:", err)
		return
	}
	if err := os.WriteFile("v2site.dat", protoBytes, os.ModePerm.Perm()); err != nil {
		fmt.Println("Failed: ", err)
	}

	// IP List
	ipBytes, err := proto.Marshal(ipList)
	if err != nil {
		fmt.Println("Failed:", err)
		return
	}
	if err := os.WriteFile("v2ip.dat", ipBytes, os.ModePerm.Perm()); err != nil {
		fmt.Println("Failed: ", err)
	}

	// Map Text
	mapDictStr := ""
	mapDictStr += "v2site:\n"
	for _, v := range siteMapList {
		mapDictStr += "    " + v + "\n"
	}
	mapDictStr += "v2ip:\n"
	for _, v := range ipMapList {
		mapDictStr += "    " + v + "\n"
	}
	mapDictByte := []byte(mapDictStr)
	if err := os.WriteFile("v2map.txt", mapDictByte, os.ModePerm.Perm()); err != nil {
		fmt.Println("Failed: ", err)
		return
	}
	// Map Text
	yamlPACStr := ""
	for _, v := range yamlPACList {
		yamlPACStr += "" + v + "\n"
	}
	yamlPACByte := []byte(yamlPACStr)
	if err := os.WriteFile("v2yaml.yaml", yamlPACByte, os.ModePerm.Perm()); err != nil {
		fmt.Println("Failed: ", err)
		return
	}
}
