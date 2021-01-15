package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto" v1.4.3
	"github.com/v2ray/v2ray-core/app/router" v4.23.2
	"github.com/v2ray/v2ray-core/infra/conf" v4.23.2
)

type vEntryType int32

const (
	vEntryTypeUnknow       vEntryType = 0
	vEntryTypeDomain       vEntryType = 1
	vEntryTypeRegex        vEntryType = 2
	vEntryTypeKeyword      vEntryType = 3
	vEntryTypeFull         vEntryType = 4
	vEntryTypeIP           vEntryType = 10
	vEntryTypeIPSubnetMask vEntryType = 11
	vEntryTypeInclud       vEntryType = 100
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
			return nil, errors.New("unknown domain type: ")
		}
	}
	return site, nil
}

func (l *vParsedIPList) toProto() (*router.GeoIP, error) {
	ip := &router.GeoIP{
		CountryCode: l.Name,
	}
	for _, entry := range l.Entry {
		if entry.Type == vEntryTypeIP || entry.Type == vEntryTypeIPSubnetMask {
			cidr, err := conf.ParseIP(entry.Value)
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
	entry.Type = vEntryTypeUnknow

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
			entry.Type = vEntryTypeInclud
		}
		entry.Value = strings.ToLower(kv[1])
		return nil
	}

	return errors.New("Invalid format: " + domain)
}

func parseIP(ip string, entry *vEntry) error {
	kv := strings.Split(ip, ":")

	entry.Type = vEntryTypeUnknow

	if len(kv) == 1 {
		entry.Type = vEntryTypeIP
		var ipString = strings.ToLower(kv[0])

		entry.Value = ipString
		return nil
	}

	if len(kv) == 2 {
		entry.Type = vEntryTypeInclud
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
		intv, err := strconv.Atoi(parts[1])
		if err != nil {
			return attribute, errors.New("invalid attribute: " + attr + ": " + err.Error())
		}
		attribute.TypedValue = &router.Domain_Attribute_IntValue{IntValue: int64(intv)}
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
	// arrPath := strings.Split(path, string(filepath.ListSeparator))
	// for _, content := range arrPath {
	// 	fullPath := filepath.Join(content, "src", "github.com", "SwordJason", "V2SiteIP", "data")
	// 	_, err := os.Stat(fullPath)
	// 	if err == nil || os.IsExist(err) {
	// 		return fullPath, nil
	// 	}
	// }

	var currentPath = getCurrentDirectory()
	var fullPath = filepath.Join(currentPath, "data")
	_, err := os.Stat(fullPath)
	if err == nil || os.IsExist(err) {
		return fullPath, nil
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
			if entry.Type == vEntryTypeInclud {
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
			if entry.Type == vEntryTypeInclud {
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

func main() {
	sourceDir, err := detectPath(os.Getenv("GOPATH"))
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
			return err
		}
		ref[list.Name] = list
		return nil
	})
	if err != nil {
		fmt.Println("Failed: ", err)
		return
	}
	protoList := new(router.GeoSiteList)
	ipList := new(router.GeoIPList)

	for _, list := range ref {
		if list.Type == vFileTypeSite {
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
			protoList.Entry = append(protoList.Entry, site)
			continue
		}
		if list.Type == vFileTypeIP {
			pipl, err := parseIPList(list, ref)
			if err != nil {
				fmt.Println("Failed: ", err)
				return
			}
			ips, err := pipl.toProto()
			if err != nil {
				fmt.Println("Failed: ", err)
				return
			}
			ipList.Entry = append(ipList.Entry, ips)
			continue
		}
	}

	// Site List
	protoBytes, err := proto.Marshal(protoList)
	if err != nil {
		fmt.Println("Failed:", err)
		return
	}
	if err := ioutil.WriteFile("v2site.dat", protoBytes, 0777); err != nil {
		fmt.Println("Failed: ", err)
	}

	// IP List
	ipBytes, err := proto.Marshal(ipList)
	if err != nil {
		fmt.Println("Failed:", err)
		return
	}
	if err := ioutil.WriteFile("v2ip.dat", ipBytes, 0777); err != nil {
		fmt.Println("Failed: ", err)
	}

}
