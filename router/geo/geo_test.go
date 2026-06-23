package geo

import (
	"math"
	"testing"
)

func TestClientLatLon(t *testing.T) {
	if la, lo, ok := ClientLatLon("19.0,72.8"); !ok || math.Abs(la-19) > 0.01 || math.Abs(lo-72.8) > 0.01 {
		t.Fatalf("lat,long parse: got %v,%v ok=%v", la, lo, ok)
	}
	if _, _, ok := ClientLatLon(" 40.0 , -83.0 "); !ok {
		t.Fatal("spaced lat,long should parse")
	}
	if _, _, ok := ClientLatLon("IN"); !ok {
		t.Fatal("country code IN should resolve")
	}
	if _, _, ok := ClientLatLon("ZZ"); ok {
		t.Fatal("unknown code ZZ must not resolve")
	}
	if _, _, ok := ClientLatLon(""); ok {
		t.Fatal("empty must not resolve")
	}
}

func TestPairDistanceKm(t *testing.T) {
	// Mumbai client; both TEEs in asia-south1 (Mumbai) -> small.
	near, ok := PairDistanceKm(19.0, 72.8, "asia-south1", "asia-south1")
	if !ok || near > 500 {
		t.Fatalf("colocated pair should be near: %v ok=%v", near, ok)
	}
	// US pair -> far, and farther than the local one.
	far, ok := PairDistanceKm(19.0, 72.8, "us-central1", "us-east-2")
	if !ok || far < 10000 || far <= near {
		t.Fatalf("US pair should be far (>%v): %v ok=%v", near, far, ok)
	}
	// Cross-continent pair: max() picks the far TEE -> large (a fallback).
	x, ok := PairDistanceKm(19.0, 72.8, "asia-south1", "us-east-2")
	if !ok || x < 10000 {
		t.Fatalf("cross-continent max should be far: %v ok=%v", x, ok)
	}
	// Unknown region -> not geo-located.
	if _, ok := PairDistanceKm(19.0, 72.8, "us-central1", "nowhere-1"); ok {
		t.Fatal("unknown region must report ok=false")
	}
}
