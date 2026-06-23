// Package geo gives the router coarse geographic placement for TEE pairs and
// clients, so /allocate can prefer a pair whose TEEs are near the client.
//
// TEE IPs are always cloud IPs, so we resolve them to a cloud region via the
// providers' published IP-range lists (fetched at startup) and map the region
// to an approximate datacenter centroid. The client location comes from an
// LB-injected header. Everything degrades safely: if the ranges aren't loaded
// or a region is unknown, geo scoring is skipped and allocation falls back to
// its prior behavior.
package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	awsRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	gcpRangesURL = "https://www.gstatic.com/ipranges/cloud.json"
)

// LatLon is a client (or pair) location; nil means "unknown" to callers.
type LatLon struct {
	Lat, Lon float64
}

type cidrEntry struct {
	net    *net.IPNet
	region string
}

var (
	mu      sync.RWMutex
	entries []cidrEntry
	loaded  bool
)

// Load fetches the AWS + GCP IP-range lists and builds the CIDR->region index.
// Best-effort: a failure leaves geo disabled (RegionForIP returns "") rather
// than erroring, so the router still allocates.
func Load(ctx context.Context, client *http.Client) error {
	aws, errA := fetchAWS(ctx, client)
	gcp, errG := fetchGCP(ctx, client)
	all := append(aws, gcp...)
	if len(all) == 0 {
		return fmt.Errorf("no IP ranges loaded (aws: %v, gcp: %v)", errA, errG)
	}
	// Longest prefix first, so RegionForIP can take the first match.
	sort.Slice(all, func(i, j int) bool {
		si, _ := all[i].net.Mask.Size()
		sj, _ := all[j].net.Mask.Size()
		return si > sj
	})
	mu.Lock()
	entries = all
	loaded = true
	mu.Unlock()
	return nil
}

// IsLoaded reports whether the IP-range index is populated.
func IsLoaded() bool {
	mu.RLock()
	defer mu.RUnlock()
	return loaded
}

// RegionForIP resolves a cloud IP to its provider region ("" if unknown or the
// index isn't loaded). ipStr may be a bare IP or host:port.
func RegionForIP(ipStr string) string {
	if h, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = h
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	mu.RLock()
	defer mu.RUnlock()
	for _, e := range entries { // sorted longest-prefix-first
		if e.net.Contains(ip) {
			return e.region
		}
	}
	return ""
}

func fetchAWS(ctx context.Context, c *http.Client) ([]cidrEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
		} `json:"prefixes"`
	}
	if err := getJSON(ctx, c, awsRangesURL, &doc); err != nil {
		return nil, err
	}
	out := make([]cidrEntry, 0, len(doc.Prefixes))
	for _, p := range doc.Prefixes {
		if _, n, err := net.ParseCIDR(p.IPPrefix); err == nil && p.Region != "" {
			out = append(out, cidrEntry{net: n, region: p.Region})
		}
	}
	return out, nil
}

func fetchGCP(ctx context.Context, c *http.Client) ([]cidrEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			Scope      string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := getJSON(ctx, c, gcpRangesURL, &doc); err != nil {
		return nil, err
	}
	out := make([]cidrEntry, 0, len(doc.Prefixes))
	for _, p := range doc.Prefixes {
		if p.IPv4Prefix == "" || p.Scope == "" || p.Scope == "global" {
			continue
		}
		if _, n, err := net.ParseCIDR(p.IPv4Prefix); err == nil {
			out = append(out, cidrEntry{net: n, region: p.Scope})
		}
	}
	return out, nil
}

func getJSON(ctx context.Context, c *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// regionCentroid maps an AWS/GCP region to an approximate datacenter lat/long.
// Coarse on purpose — region-level proximity is all the selector needs.
var regionCentroid = map[string][2]float64{
	// AWS
	"us-east-1": {38.9, -77.5}, "us-east-2": {40.0, -83.0}, "us-west-1": {37.4, -121.9}, "us-west-2": {45.9, -119.7},
	"ca-central-1": {45.5, -73.6}, "sa-east-1": {-23.5, -46.6},
	"eu-west-1": {53.3, -6.3}, "eu-west-2": {51.5, -0.1}, "eu-west-3": {48.9, 2.4}, "eu-central-1": {50.1, 8.7}, "eu-north-1": {59.3, 18.1},
	"ap-south-1": {19.1, 72.9}, "ap-south-2": {17.4, 78.5}, "ap-southeast-1": {1.35, 103.8}, "ap-southeast-2": {-33.9, 151.2},
	"ap-northeast-1": {35.7, 139.7}, "ap-northeast-2": {37.6, 127.0}, "ap-east-1": {22.3, 114.2},
	"me-central-1": {24.5, 54.4}, "me-south-1": {26.1, 50.6},
	// GCP
	"us-central1": {41.3, -95.9}, "us-east1": {33.2, -80.0}, "us-east4": {39.0, -77.5}, "us-east5": {39.96, -83.0},
	"us-west1": {45.6, -121.2}, "us-west2": {34.0, -118.2}, "us-west4": {36.2, -115.1},
	"northamerica-northeast1": {45.5, -73.6}, "southamerica-east1": {-23.5, -46.6},
	"europe-west1": {50.5, 3.8}, "europe-west2": {51.5, -0.1}, "europe-west3": {50.1, 8.7}, "europe-west4": {53.4, 6.8}, "europe-north1": {60.6, 27.2},
	"asia-south1": {19.1, 72.9}, "asia-south2": {28.6, 77.2}, "asia-southeast1": {1.35, 103.8}, "asia-southeast2": {-6.2, 106.8},
	"asia-east1": {24.0, 120.7}, "asia-east2": {22.3, 114.2}, "asia-northeast1": {35.7, 139.7}, "asia-northeast3": {37.6, 127.0},
	"australia-southeast1": {-33.9, 151.2}, "me-central1": {24.5, 54.4}, "me-west1": {32.1, 34.9},
}

// clientRegionCentroid maps an ISO 3166-1 alpha-2 country (GCP LB {client_region})
// or a 2-letter continent code to a centroid, for the X-Client-Region header.
var clientRegionCentroid = map[string][2]float64{
	"US": {39.8, -98.6}, "CA": {56.1, -106.3}, "MX": {23.6, -102.6}, "BR": {-14.2, -51.9}, "AR": {-38.4, -63.6},
	"GB": {54.0, -2.0}, "IE": {53.4, -8.0}, "FR": {46.2, 2.2}, "DE": {51.2, 10.4}, "NL": {52.1, 5.3}, "ES": {40.5, -3.7}, "IT": {41.9, 12.6}, "SE": {60.1, 18.6}, "PL": {51.9, 19.1},
	"IN": {22.0, 79.0}, "SG": {1.35, 103.8}, "ID": {-2.5, 118.0}, "JP": {36.2, 138.3}, "KR": {35.9, 127.8}, "HK": {22.3, 114.2}, "TW": {23.7, 121.0}, "CN": {35.9, 104.2},
	"AE": {23.4, 53.8}, "SA": {23.9, 45.1}, "BH": {26.0, 50.6},
	"AU": {-25.3, 133.8}, "NZ": {-40.9, 174.9}, "ZA": {-30.6, 22.9}, "NG": {9.1, 8.7},
	// continent fallbacks
	"NA": {40.0, -100.0}, "EU": {50.0, 10.0}, "AS": {30.0, 100.0}, "OC": {-25.0, 135.0}, "AF": {2.0, 20.0},
}

// ClientLatLon parses the LB-injected client-location header. Accepts either
// "lat,long" (e.g. GCP {client_city_lat_long}) or a region/country code
// resolved via clientRegionCentroid. Returns ok=false if it can't.
func ClientLatLon(v string) (lat, lon float64, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, 0, false
	}
	if i := strings.IndexByte(v, ','); i >= 0 {
		la, e1 := strconv.ParseFloat(strings.TrimSpace(v[:i]), 64)
		lo, e2 := strconv.ParseFloat(strings.TrimSpace(v[i+1:]), 64)
		if e1 == nil && e2 == nil {
			return la, lo, true
		}
	}
	if c, found := clientRegionCentroid[strings.ToUpper(v)]; found {
		return c[0], c[1], true
	}
	return 0, 0, false
}

// PairDistanceKm scores a pair for a client at (clat,clon): the great-circle
// distance to the FARTHER of the two TEEs (the latency bottleneck, since the
// client talks to both). ok=false if either TEE region is unknown — such a
// pair has no geo and the caller should treat it as a fallback.
func PairDistanceKm(clat, clon float64, teekRegion, teetRegion string) (float64, bool) {
	k, okk := regionCentroid[teekRegion]
	t, okt := regionCentroid[teetRegion]
	if !okk || !okt {
		return 0, false
	}
	return math.Max(haversineKm(clat, clon, k[0], k[1]), haversineKm(clat, clon, t[0], t[1])), true
}

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	p := math.Pi / 180
	dlat := (lat2 - lat1) * p
	dlon := (lon2 - lon1) * p
	a := math.Sin(dlat/2)*math.Sin(dlat/2) +
		math.Cos(lat1*p)*math.Cos(lat2*p)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return r * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}
