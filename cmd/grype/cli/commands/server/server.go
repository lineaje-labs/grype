package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/hex"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	jsonpresenter "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
)

const defaultRefreshInterval = 2 * time.Hour

// Config holds server configuration.
type Config struct {
	Addr            string
	ID              clio.Identification
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	MaxRequestSize  int64
	RefreshInterval time.Duration // how often to refresh the vulnerability DB; 0 disables
	ByCVE           bool          // orient results by CVE ID instead of the original advisory ID
}

func DefaultConfig(id clio.Identification) Config {
	return Config{
		Addr:            ":8080",
		ID:              id,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    120 * time.Second,
		MaxRequestSize:  1 << 10, // 1 KiB — PURLs are small
		RefreshInterval: defaultRefreshInterval,
		ByCVE:           true,
	}
}

// Server loads the vulnerability DB once at startup (with a forced update), serves
// concurrent scan requests, and periodically refreshes the DB in the background.
//
// The refresh swap is zero-downtime: scan() holds mu.RLock() for its entire
// duration, so refreshDB()'s mu.Lock() blocks until every in-flight request
// finishes before atomically replacing the provider.
type Server struct {
	cfg         Config
	opts        *options.Grype
	vp          vulnerability.Provider
	dbReader    v6.Reader
	stat        *vulnerability.ProviderStatus
	mu          sync.RWMutex // RLock held by every in-flight scan; Lock used by refreshDB
	srv         *http.Server
	stopRefresh context.CancelFunc
}

type scanRequest struct {
	PURL string `json:"purl"`
}

type vulnRequest struct {
	ID string `json:"id"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// New creates a Server, forces a DB update on startup, and launches the
// background refresh goroutine. Call Close when done.
func New(cfg Config) (*Server, error) {
	opts := options.DefaultGrype(cfg.ID)
	// Disable grype's per-scan auto-update; the server manages updates itself.
	opts.DB.AutoUpdate = false
	opts.ByCVE = cfg.ByCVE

	slog.Info("updating vulnerability database…")
	// Always force-update the DB on startup so the server starts with current data.
	vp, dbReader, stat, err := grype.LoadVulnerabilityDBWithReader(opts.ToClientConfig(), opts.ToCuratorConfig(), true)
	if err != nil {
		return nil, fmt.Errorf("load vulnerability db: %w", err)
	}
	if stat != nil && stat.Error != nil {
		return nil, fmt.Errorf("vulnerability db: %w", stat.Error)
	}
	slog.Info("vulnerability database ready", "built", stat.Built.UTC().Format(time.RFC3339), "schema", stat.SchemaVersion)

	s := &Server{cfg: cfg, opts: opts, vp: vp, dbReader: dbReader, stat: stat}

	mux := http.NewServeMux()
	mux.HandleFunc("/scan", s.handleScan)
	mux.HandleFunc("/vuln", s.handleVuln)
	mux.HandleFunc("/health", s.handleHealth)

	s.srv = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	if cfg.RefreshInterval > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		s.stopRefresh = cancel
		go s.runRefresher(ctx, cfg.RefreshInterval)
	}

	return s, nil
}

// ListenAndServe starts the HTTP server. Blocks until shutdown.
func (s *Server) ListenAndServe() error {
	slog.Info("grype REST API listening", "addr", s.cfg.Addr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// Close stops the background refresh goroutine and releases the vulnerability provider.
func (s *Server) Close() error {
	if s.stopRefresh != nil {
		s.stopRefresh()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vp != nil {
		return s.vp.Close()
	}
	return nil
}

// runRefresher wakes every interval and refreshes the vulnerability DB.
func (s *Server) runRefresher(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Info("starting scheduled vulnerability DB refresh")
			if err := s.refreshDB(); err != nil {
				slog.Error("vulnerability DB refresh failed", "err", err)
			}
		}
	}
}

// refreshDB downloads/updates the vulnerability DB, then waits for all
// in-flight requests to finish (by acquiring mu.Lock) before atomically
// swapping in the new provider.
func (s *Server) refreshDB() error {
	// Load the new provider while requests continue using the old one.
	newVP, newReader, newStat, err := grype.LoadVulnerabilityDBWithReader(s.opts.ToClientConfig(), s.opts.ToCuratorConfig(), true)
	if err != nil {
		return fmt.Errorf("download updated db: %w", err)
	}
	if newStat != nil && newStat.Error != nil {
		_ = newVP.Close()
		return fmt.Errorf("updated db status: %w", newStat.Error)
	}

	// Acquiring the write lock blocks until every in-flight scan releases its
	// read lock, giving us a clean moment with zero active requests.
	s.mu.Lock()
	oldVP := s.vp
	s.vp = newVP
	s.dbReader = newReader
	s.stat = newStat
	s.mu.Unlock()

	slog.Info("vulnerability database swapped", "built", newStat.Built.UTC().Format(time.RFC3339))

	// Close the old provider after releasing the lock so we don't block scans.
	if oldVP != nil {
		if err := oldVP.Close(); err != nil {
			slog.Warn("closing old vulnerability provider", "err", err)
		}
	}
	return nil
}

// handleHealth returns 200 with DB metadata so callers can verify the server is ready.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	stat := s.stat
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if stat == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: "database not loaded"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"db": map[string]string{
			"built":  stat.Built.UTC().Format(time.RFC3339),
			"schema": stat.SchemaVersion,
		},
	})
}

// handleScan accepts:
//
//	GET  /scan?purl=pkg:npm/express@4.17.1
//	POST /scan   {"purl":"pkg:npm/express@4.17.1"}
//
// and returns the same JSON document as `grype <purl> -o json`.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	purl, err := extractPURL(w, r, s.cfg.MaxRequestSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	doc, httpStatus, err := s.scan(r.Context(), purl)
	if err != nil {
		writeError(w, httpStatus, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	p := jsonpresenter.NewPresenter(models.PresenterConfig{
		ID:       s.cfg.ID,
		Document: doc,
	})
	if err := p.Present(w); err != nil {
		slog.Error("write scan response", "err", err)
	}
}

// handleVuln accepts:
//
//	GET  /vuln?id=CVE-2021-44228
//	POST /vuln   {"id":"CVE-2021-44228"}
//
// and returns the same JSON as `grype db search <vuln-id> -o json`.
func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request) {
	vulnID, err := extractVulnID(w, r, s.cfg.MaxRequestSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.RLock()
	rdr := s.dbReader
	s.mu.RUnlock()

	if rdr == nil {
		writeError(w, http.StatusServiceUnavailable, "database not loaded")
		return
	}

	results, err := dbsearch.FindVulnerabilities(rdr, dbsearch.VulnerabilitiesOptions{
		Vulnerability: v6.VulnerabilitySpecifiers{{Name: vulnID}},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("search vulnerabilities: %v", err))
		return
	}

	if results == nil {
		results = []dbsearch.Vulnerability{}
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(results); err != nil {
		slog.Error("write vuln response", "err", err)
	}
}

// extractVulnID reads the vulnerability ID from the query string (GET) or JSON body (POST).
func extractVulnID(w http.ResponseWriter, r *http.Request, maxBody int64) (string, error) {
	var id string
	switch r.Method {
	case http.MethodGet:
		id = r.URL.Query().Get("id")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		var req vulnRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return "", fmt.Errorf("decode request body: %w", err)
		}
		id = req.ID
	default:
		return "", fmt.Errorf("method %s not allowed; use GET or POST", r.Method)
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("id is required")
	}
	return id, nil
}

// scan executes the full grype pipeline for a single PURL.
//
// mu.RLock is held for the entire call so that refreshDB's mu.Lock waits for
// all in-flight scans to finish before swapping the provider.
func (s *Server) scan(ctx context.Context, purl string) (models.Document, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	packages, pkgCtx, _, err := pkg.Provide(purl, buildProviderConfig(s.opts))
	if err != nil {
		return models.Document{}, http.StatusBadRequest, fmt.Errorf("catalog packages from purl: %w", err)
	}

	vexProc, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents:   s.opts.VexDocuments,
		IgnoreRules: s.opts.Ignore,
	})
	if err != nil {
		return models.Document{}, http.StatusInternalServerError, fmt.Errorf("create vex processor: %w", err)
	}

	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: s.vp,
		IgnoreRules:           s.opts.Ignore,
		NormalizeByCVE:        s.opts.ByCVE,
		FailSeverity:          s.opts.FailOnSeverity(),
		Matchers:              buildMatchers(s.opts),
		VexProcessor:          vexProc,
	}

	remaining, ignored, err := vulnMatcher.FindMatchesContext(ctx, packages, pkgCtx)
	if err != nil && !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
		return models.Document{}, http.StatusInternalServerError, fmt.Errorf("find vulnerability matches: %w", err)
	}

	doc, err := models.NewDocument(
		s.cfg.ID,
		packages,
		pkgCtx,
		*remaining,
		ignored,
		s.vp,
		s.opts,
		buildDBInfo(s.stat, s.vp),
		models.SortStrategy(s.opts.SortBy.Criteria),
		s.opts.Timestamp,
		nil,
		"",
	)
	if err != nil {
		return models.Document{}, http.StatusInternalServerError, fmt.Errorf("build document: %w", err)
	}
	return doc, http.StatusOK, nil
}

// extractPURL reads the PURL from the query string (GET) or JSON body (POST).
func extractPURL(w http.ResponseWriter, r *http.Request, maxBody int64) (string, error) {
	var purl string
	switch r.Method {
	case http.MethodGet:
		purl = r.URL.Query().Get("purl")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return "", fmt.Errorf("decode request body: %w", err)
		}
		purl = req.PURL
	default:
		return "", fmt.Errorf("method %s not allowed; use GET or POST", r.Method)
	}
	purl = strings.TrimSpace(purl)
	if purl == "" {
		return "", fmt.Errorf("purl is required")
	}
	return purl, nil
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

// buildProviderConfig mirrors getProviderConfig in cmd/grype/cli/commands/root.go.
func buildProviderConfig(opts *options.Grype) pkg.ProviderConfig {
	cfg := syft.DefaultCreateSBOMConfig()
	cfg.Packages.JavaArchive.IncludeIndexedArchives = opts.Search.IncludeIndexedArchives
	cfg.Packages.JavaArchive.IncludeUnindexedArchives = opts.Search.IncludeUnindexedArchives
	cfg.Packages.Golang = cfg.Packages.Golang.WithCaptureSymbols(cataloging.SymbolScopeAll)
	cfg.Compliance.MissingVersion = cataloging.ComplianceActionDrop

	return pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:        opts.Registry.ToOptions(),
			Exclusions:             opts.Exclusions,
			SBOMOptions:            cfg,
			Platform:               opts.Platform,
			Name:                   opts.Name,
			DefaultImagePullSource: opts.DefaultImagePullSource,
			Sources:                opts.From,
		},
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: opts.GenerateMissingCPEs,
		},
	}
}

// buildMatchers mirrors getMatchers in cmd/grype/cli/commands/root.go.
func buildMatchers(opts *options.Grype) []match.Matcher {
	return matcher.NewDefaultMatchers(matcher.Config{
		Java: java.MatcherConfig{
			ExternalSearchConfig: opts.ExternalSources.ToJavaMatcherConfig(),
			UseCPEs:              opts.Match.Java.UseCPEs,
		},
		Ruby:       ruby.MatcherConfig(opts.Match.Ruby),
		Python:     python.MatcherConfig(opts.Match.Python),
		Dotnet:     dotnet.MatcherConfig(opts.Match.Dotnet),
		Javascript: javascript.MatcherConfig(opts.Match.Javascript),
		Golang: golang.MatcherConfig{
			UseCPEs:                                opts.Match.Golang.UseCPEs,
			AlwaysUseCPEForStdlib:                  opts.Match.Golang.AlwaysUseCPEForStdlib,
			AllowMainModulePseudoVersionComparison: opts.Match.Golang.AllowMainModulePseudoVersionComparison,
		},
		Rust:  rust.MatcherConfig(opts.Match.Rust),
		Hex:   hex.MatcherConfig(opts.Match.Hex),
		Stock: stock.MatcherConfig(opts.Match.Stock),
		Dpkg: dpkg.MatcherConfig{
			MissingEpochStrategy: opts.Match.Dpkg.MissingEpochStrategy,
			UseCPEsForEOL:        opts.Match.Dpkg.UseCPEsForEOL,
		},
		Rpm: rpm.MatcherConfig{
			MissingEpochStrategy: opts.Match.Rpm.MissingEpochStrategy,
			UseCPEsForEOL:        opts.Match.Rpm.UseCPEsForEOL,
		},
	})
}

func buildDBInfo(stat *vulnerability.ProviderStatus, vp vulnerability.Provider) any {
	var providers map[string]vulnerability.DataProvenance
	if vp != nil {
		if dpr, ok := vp.(vulnerability.StoreMetadataProvider); ok {
			if dps, err := dpr.DataProvenance(); err == nil {
				providers = dps
			}
		}
	}
	return struct {
		Status    *vulnerability.ProviderStatus           `json:"status"`
		Providers map[string]vulnerability.DataProvenance `json:"providers"`
	}{
		Status:    stat,
		Providers: providers,
	}
}
