package collector

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/iamhalje/defectdojo-exporter/lib/defectdojo"
)

func count(g *prometheus.GaugeVec) int {
	ch := make(chan prometheus.Metric, 1000)
	g.Collect(ch)
	close(ch)
	return len(ch)
}

func value(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	_ = g.Write(m)
	return m.GetGauge().GetValue()
}

// seed exports one active series for product/productType the way the collector does.
func seed(product, productType string) {
	defectdojo.MU.Lock()
	defer defectdojo.MU.Unlock()
	defectdojo.VulnActiveGauge.WithLabelValues(product, productType, "critical", "79").Set(3)
	defectdojo.VulnFixTimeDaysSumGauge.WithLabelValues(product, productType, "critical").Set(10)
	if defectdojo.PrevActive[product] == nil {
		defectdojo.PrevActive[product] = map[string]float64{}
	}
	defectdojo.PrevActive[product]["critical|79"] = 3
	defectdojo.ProductTypes[product] = productType
}

func reset() {
	defectdojo.MU.Lock()
	defer defectdojo.MU.Unlock()
	for p := range defectdojo.KnownProducts() {
		defectdojo.ForgetProduct(p)
	}
}

func TestPruneProductsDropsDeletedProducts(t *testing.T) {
	reset()
	seed("Blackpearl", "CRM")
	seed("CRM Infra", "CRM")

	pruneProducts([]defectdojo.Product{{Name: "Blackpearl"}})

	if got := value(defectdojo.VulnActiveGauge.WithLabelValues("Blackpearl", "CRM", "critical", "79")); got != 3 {
		t.Errorf("kept product lost its value: got %v", got)
	}
	// WithLabelValues above re-created only the Blackpearl series; CRM Infra must be gone.
	if n := count(defectdojo.VulnActiveGauge); n != 1 {
		t.Errorf("active series after prune: got %d, want 1", n)
	}
	if n := count(defectdojo.VulnFixTimeDaysSumGauge); n != 1 {
		t.Errorf("fix-time series after prune: got %d, want 1", n)
	}
	defectdojo.MU.Lock()
	defer defectdojo.MU.Unlock()
	if _, ok := defectdojo.PrevActive["CRM Infra"]; ok {
		t.Error("state for deleted product was kept")
	}
}

func TestForgetProductOnTypeMove(t *testing.T) {
	reset()
	seed("Host: cor-st1", "CRM")
	defectdojo.MU.Lock()
	defectdojo.ForgetProduct("Host: cor-st1")
	defectdojo.MU.Unlock()
	seed("Host: cor-st1", "Infrastructure")

	if n := count(defectdojo.VulnActiveGauge); n != 1 {
		t.Fatalf("active series after move: got %d, want 1 (old product_type label must be gone)", n)
	}
	if got := value(defectdojo.VulnActiveGauge.WithLabelValues("Host: cor-st1", "Infrastructure", "critical", "79")); got != 3 {
		t.Errorf("moved product value: got %v, want 3", got)
	}
}

func TestEnsureProductPresenceForCleanProduct(t *testing.T) {
	reset()
	ensureProductPresence("Host: T4", "Edge")
	if n := count(defectdojo.VulnActiveGauge); n != 1 {
		t.Fatalf("clean product series: got %d, want 1", n)
	}
	if got := value(defectdojo.VulnActiveGauge.WithLabelValues("Host: T4", "Edge", "info", "0")); got != 0 {
		t.Errorf("placeholder value: got %v, want 0", got)
	}
	// A product that already has findings gets no placeholder.
	seed("Host: qa2", "Infrastructure")
	ensureProductPresence("Host: qa2", "Infrastructure")
	if n := count(defectdojo.VulnActiveGauge); n != 2 {
		t.Errorf("series after presence check on product with findings: got %d, want 2", n)
	}
}
