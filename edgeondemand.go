package edgeondemand

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/koltyakov/gosip"
	"github.com/koltyakov/gosip/cpass"

	edgecookies "sharepoint-go/edgecookies"
)

var (
	// cookieCache: host -> *Cookies (cache em memória, thread-safe via sync.Map)
	cookieCache sync.Map

	// refreshLocks: host -> *sync.Mutex
	// usado para serializar refresh de cookies por domínio e assim evitar múltiplos Edge a arrancar em paralelo.
	refreshLocks sync.Map

	// crypter: usado para cifrar/decifrar cache em disco
	crypter = cpass.Cpass("")
)

// getHostMutex devolve (e cria se necessário) um mutex por host.
func getHostMutex(host string) *sync.Mutex {
	mu, _ := refreshLocks.LoadOrStore(host, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// AuthCnfg implementa gosip.AuthCnfg-like para a nossa estratégia edgeondemand.
type AuthCnfg struct {
	SiteURL     string      `json:"siteUrl"`
	EdgeOptions *EdgeConfig `json:"edgeOptions,omitempty"`
}

// EdgeConfig controla como obtemos cookies via Edge/Chromium.
type EdgeConfig struct {
	EdgePath                   string `json:"edgePath,omitempty"`
	UserDataDir                string `json:"userDataDir,omitempty"`
	ProfileDir                 string `json:"profileDir,omitempty"`
	Headless                   bool   `json:"headless,omitempty"`
	TimeoutSeconds             int    `json:"timeoutSeconds,omitempty"`
	Debug                      bool   `json:"debug,omitempty"`
	AutoProfile                bool   `json:"autoProfile,omitempty"`                // auto-detectar perfil real quando userDataDir=""
	InteractiveFallback        bool   `json:"interactiveFallback,omitempty"`        // se headless falhar / requerer MFA, tentar janela visível
	AllowTempProfileWhenLocked bool   `json:"allowTempProfileWhenLocked,omitempty"` // se o perfil real estiver em uso, usar perfil temporário
	ForceTempProfile           bool   `json:"forceTempProfile,omitempty"`           // força perfil temporário (ignora perfil real)
	RefreshSkewSeconds         int    `json:"refreshSkewSeconds,omitempty"`         // renovar Xs antes de expirar; se <=0 usamos 300
}

// normalizeEdgeOptions garante defaults mínimos seguros/úteis.
func (c *AuthCnfg) normalizeEdgeOptions() {
	if c.EdgeOptions == nil {
		c.EdgeOptions = &EdgeConfig{}
	}

	if c.EdgeOptions.TimeoutSeconds <= 0 {
		c.EdgeOptions.TimeoutSeconds = 180
	}

	if c.EdgeOptions.RefreshSkewSeconds <= 0 {
		c.EdgeOptions.RefreshSkewSeconds = 300
	}

	// Se não foi fornecido um userDataDir explícito e AutoProfile está false,
	// ligamos AutoProfile para tentar descobrir o perfil real do Edge.
	if !c.EdgeOptions.AutoProfile && c.EdgeOptions.UserDataDir == "" {
		c.EdgeOptions.AutoProfile = true
	}
}

// ====== API exigida pelo gosip.Strategy ====== //

func (c *AuthCnfg) ReadConfig(privateFile string) error {
	f, err := os.Open(privateFile)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	b, _ := io.ReadAll(f)
	return c.ParseConfig(b)
}

func (c *AuthCnfg) ParseConfig(b []byte) error {
	return json.Unmarshal(b, &c)
}

func (c *AuthCnfg) WriteConfig(privateFile string) error {
	cfg := &AuthCnfg{
		SiteURL:     c.SiteURL,
		EdgeOptions: c.EdgeOptions,
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(privateFile, out, 0644)
}

func (c *AuthCnfg) GetSiteURL() string  { return c.SiteURL }
func (c *AuthCnfg) GetStrategy() string { return "edgeondemand" }

func (c *AuthCnfg) SetAuth(req *http.Request, _ *gosip.SPClient) error {
	authCookie, _, err := c.GetAuth()
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", authCookie)
	return nil
}

// ====== Fluxo principal com cache (mem/disk) + refresh pró-ativo ====== //

func (c *AuthCnfg) GetAuth() (string, int64, error) {
	// Normalizar defaults antes de usar as opções
	c.normalizeEdgeOptions()

	u, err := url.Parse(c.SiteURL)
	if err != nil || u.Host == "" {
		return "", 0, fmt.Errorf("siteUrl inválido: %v", c.SiteURL)
	}

	// logger simples (stderr) para marcadores do fluxo
	dbg := func(string, ...any) {}
	if c.EdgeOptions.Debug {
		dbg = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "[edgeondemand] "+f+"\n", a...) }
	}

	skew := int64(c.EdgeOptions.RefreshSkewSeconds)

	// 1) cache em memória
	if v, ok := cookieCache.Load(u.Host); ok {
		if cc, _ := v.(*Cookies); cc != nil && !cc.isExpiredWithSkew(skew) {
			if c.EdgeOptions.Debug {
				dbg("using IN-MEMORY cache for %s (site=%s cachedAt=%s exp=%d in %s)",
					u.Host,
					cc.SiteURL,
					cc.CachedAt,
					cc.getExpire(),
					time.Until(time.Unix(cc.getExpire(), 0)).Round(time.Second),
				)
			}
			return cc.toString(), cc.getExpire(), nil
		}
		if c.EdgeOptions.Debug {
			if old, _ := v.(*Cookies); old != nil {
				dbg("memory cache for %s is stale (exp=%d); refreshing", u.Host, old.getExpire())
			} else {
				dbg("memory cache for %s is stale; refreshing", u.Host)
			}
		}
	}

	// 2) cache em disco
	if cc, _ := c.getCookieDiskCache(); cc != nil {
		if !cc.isExpiredWithSkew(skew) {
			if c.EdgeOptions.Debug {
				dbg("using DISK cache for %s (site=%s cachedAt=%s exp=%d in %s)",
					u.Host,
					cc.SiteURL,
					cc.CachedAt,
					cc.getExpire(),
					time.Until(time.Unix(cc.getExpire(), 0)).Round(time.Second),
				)
			}
			cookieCache.Store(u.Host, cc)
			return cc.toString(), cc.getExpire(), nil
		}
		if c.EdgeOptions.Debug {
			dbg("disk cache for %s is stale (exp=%d); refreshing", u.Host, cc.getExpire())
		}
	}

	// 3) Refresh on-demand (protegido por lock por host)
	mu := getHostMutex(u.Host)
	mu.Lock()
	defer mu.Unlock()

	// Double-check depois do lock (pode já ter sido renovado mean-time)
	if v, ok := cookieCache.Load(u.Host); ok {
		if cc, _ := v.(*Cookies); cc != nil && !cc.isExpiredWithSkew(skew) {
			if c.EdgeOptions.Debug {
				dbg("after-lock: using IN-MEMORY cache for %s (site=%s cachedAt=%s exp=%d in %s)",
					u.Host,
					cc.SiteURL,
					cc.CachedAt,
					cc.getExpire(),
					time.Until(time.Unix(cc.getExpire(), 0)).Round(time.Second),
				)
			}
			return cc.toString(), cc.getExpire(), nil
		}
	}

	if cc, _ := c.getCookieDiskCache(); cc != nil {
		if !cc.isExpiredWithSkew(skew) {
			if c.EdgeOptions.Debug {
				dbg("after-lock: using DISK cache for %s (site=%s cachedAt=%s exp=%d in %s)",
					u.Host,
					cc.SiteURL,
					cc.CachedAt,
					cc.getExpire(),
					time.Until(time.Unix(cc.getExpire(), 0)).Round(time.Second),
				)
			}
			cookieCache.Store(u.Host, cc)
			return cc.toString(), cc.getExpire(), nil
		}
	}

	// Se chegámos aqui, temos mesmo de ir pedir cookies novas ao Edge.
	if c.EdgeOptions.Debug {
		dbg("no valid cache, launching Edge flow for %s", u.Host)
	}

	cc, err := c.onDemandAuthFlow()
	if err != nil {
		return "", 0, err
	}

	// anotar metadados antes de guardar
	cc.Host = u.Host
	cc.SiteURL = c.SiteURL
	cc.CachedAt = time.Now().UTC().Format(time.RFC3339)

	_ = c.cacheCookieToDisk(cc)
	cookieCache.Store(u.Host, cc)

	if c.EdgeOptions.Debug {
		dbg("cached NEW cookies for %s (site=%s cachedAt=%s exp=%d in %s)",
			u.Host,
			cc.SiteURL,
			cc.CachedAt,
			cc.getExpire(),
			time.Until(time.Unix(cc.getExpire(), 0)).Round(time.Second),
		)
	}
	return cc.toString(), cc.getExpire(), nil
}

// onDemandAuthFlow: arranca Edge e tenta obter cookies válidas para o tenant,
// respeitando as preferências do utilizador.
func (c *AuthCnfg) onDemandAuthFlow() (*Cookies, error) {
	u, _ := url.Parse(c.SiteURL)

	// Já normalizámos EdgeOptions em GetAuth(), mas reafirmamos defaults de segurança aqui.
	timeout := time.Duration(c.EdgeOptions.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 180 * time.Second
	}

	// autoProfile:
	autoProfile := c.EdgeOptions.AutoProfile
	if !autoProfile && c.EdgeOptions.UserDataDir == "" {
		// Sem diretório explícito e autoProfile=false é estranho → tentar descobrir perfil real na mesma
		autoProfile = true
	}

	interactiveFallback := c.EdgeOptions.InteractiveFallback
	allowTempWhenLocked := c.EdgeOptions.AllowTempProfileWhenLocked
	forceTemp := c.EdgeOptions.ForceTempProfile

	dbg := func(string, ...any) {}
	if c.EdgeOptions.Debug {
		dbg = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "[edgeondemand] "+f+"\n", a...) }
	}

	// === Seleção inicial de perfil: real vs temporário ===
	var (
		realUserData   string
		realProfileDir string
		useTempProfile bool
	)

	if forceTemp {
		// O utilizador pediu explicitamente perfil temporário.
		useTempProfile = true
	} else {
		// tentar descobrir perfil real
		if autoProfile && c.EdgeOptions.UserDataDir == "" {
			if guess, err := edgecookies.DetectDefaultUserProfile(); err == nil {
				realUserData = guess.UserDataDir
				realProfileDir = guess.ProfileDir
			}
		} else {
			realUserData = c.EdgeOptions.UserDataDir
			realProfileDir = c.EdgeOptions.ProfileDir
		}

		// verificar se o perfil está bloqueado (Edge já aberto / em background)
		locked := edgecookies.IsUserDataDirLocked(realUserData)

		// Se estiver bloqueado e o utilizador permitir fallback temporário,
		// então marcamos para usar perfil temp.
		if locked && allowTempWhenLocked {
			useTempProfile = true
		}

		if c.EdgeOptions.Debug {
			dbg("realUserData: %s", realUserData)
			dbg("realProfileDir: %s", realProfileDir)
			dbg("forceTempProfile: %v", forceTemp)
			dbg("edgecookies.IsUserDataDirLocked(realUserData): %v", locked)
			dbg("allowTempWhenLocked: %v", allowTempWhenLocked)
			dbg("useTempProfile (after lock decision): %v", useTempProfile)
		}
	}

	// dump de modo resolvido (antes de tentar abrir o Edge)
	if c.EdgeOptions.Debug {
		dbg(
			"resolved edge mode: autoProfile=%v headlessFirst=%v interactiveFallback=%v allowTempWhenLocked=%v forceTemp=%v useTempProfileInitially=%v realUserData=%q realProfileDir=%q timeout=%s",
			autoProfile,
			true,
			interactiveFallback,
			allowTempWhenLocked,
			forceTemp,
			useTempProfile,
			realUserData,
			realProfileDir,
			timeout,
		)
	}

	// helper: construir Options para edgecookies.ListCookies/GetCookie
	build := func(headless bool, temp bool) edgecookies.Options {
		opt := edgecookies.Options{
			EdgePath:    c.EdgeOptions.EdgePath,
			UserDataDir: realUserData,
			ProfileDir:  realProfileDir,
			Headless:    headless,
			Timeout:     timeout,
			Debug:       c.EdgeOptions.Debug,
		}
		if temp {
			// Força perfil temporário: edgecookies irá criar UserDataDir temporário
			// e limpar no fim.
			opt.UserDataDir = ""
			opt.ProfileDir = ""
		}
		return opt
	}

	// helper: arranca Edge e recolhe cookies
	call := func(opt edgecookies.Options) ([]*network.Cookie, error) {
		return edgecookies.ListCookies(c.SiteURL, opt)
	}

	// helper: detetar erro típico de perfil já em uso
	isProfileInUseErr := func(err error) bool {
		if err == nil {
			return false
		}
		s := strings.ToLower(err.Error())
		return strings.Contains(s, "existing browser session")
	}

	// === Tentativa 1: headless, usando o perfil escolhido (real ou temporário)
	cs, err := call(build(true, useTempProfile))
	if isProfileInUseErr(err) && allowTempWhenLocked && !useTempProfile {
		// Edge disse "existing browser session"
		// => vamos tentar imediatamente com perfil temporário em headless.
		useTempProfile = true
		if c.EdgeOptions.Debug {
			dbg("got 'existing browser session' (headless), switching to TEMP and retrying headless")
		}
		cs, err = call(build(true, useTempProfile))
	}
	if err == nil {
		filtered := filterForHost(cs, u.Host)
		if hasAuthCookies(filtered) || len(filtered) > 0 {
			return cookiesFromChromedp(u.Host, filtered), nil
		}
	}

	// === Tentativa 2: modo interativo (janela), SE permitido.
	if interactiveFallback {
		cs, err = call(build(false, useTempProfile))
		if isProfileInUseErr(err) && allowTempWhenLocked && !useTempProfile {
			useTempProfile = true
			if c.EdgeOptions.Debug {
				dbg("got 'existing browser session' (headful), switching to TEMP and retrying headful")
			}
			cs, err = call(build(false, useTempProfile))
		}
		if err == nil {
			filtered := filterForHost(cs, u.Host)
			if hasAuthCookies(filtered) || len(filtered) > 0 {
				return cookiesFromChromedp(u.Host, filtered), nil
			}
		} else {
			return nil, err
		}
	}

	return nil, fmt.Errorf("não foi possível obter cookies válidas para %s", c.SiteURL)
}

// ====== Cache em disco ====== //

func (c *AuthCnfg) CleanCookieCache() error {
	path := c.getCookieCachePath()

	u, err := url.Parse(c.SiteURL)
	if err != nil {
		return err
	}

	// limpar cache em memória
	cookieCache.Delete(u.Host)

	// apagar ficheiro em disco, se existir
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (c *AuthCnfg) cacheCookieToDisk(cookies *Cookies) error {
	tmpDir := filepath.Join(os.TempDir(), "gosip")
	path := c.getCookieCachePath()

	// garantir metadados
	u, _ := url.Parse(c.SiteURL)
	if cookies.Host == "" && u != nil {
		cookies.Host = u.Host
	}
	if cookies.SiteURL == "" {
		cookies.SiteURL = c.SiteURL
	}
	if cookies.CachedAt == "" {
		cookies.CachedAt = time.Now().UTC().Format(time.RFC3339)
	}

	b, err := json.Marshal(cookies)
	if err != nil {
		return err
	}

	enc, _ := crypter.Encode(string(b))

	_ = os.MkdirAll(tmpDir, os.ModePerm)

	// escrever ficheiro cifrado com 0600
	return os.WriteFile(path, []byte(enc), 0600)
}

func (c *AuthCnfg) getCookieDiskCache() (*Cookies, error) {
	path := c.getCookieCachePath()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	dec, _ := crypter.Decode(string(b))

	out := &Cookies{}
	if err := json.Unmarshal([]byte(dec), out); err != nil {
		return nil, err
	}

	// preencher metadados ausentes (backward compat)
	u, _ := url.Parse(c.SiteURL)
	if out.Host == "" && u != nil {
		out.Host = u.Host
	}
	if out.SiteURL == "" {
		out.SiteURL = c.SiteURL
	}
	// CachedAt pode ficar vazio para ficheiros antigos, não faz mal.

	return out, nil
}

func (c *AuthCnfg) getCookieCachePath() string {
	tmpDir := filepath.Join(os.TempDir(), "gosip")
	u, _ := url.Parse(c.SiteURL)
	return filepath.Join(tmpDir, c.GetStrategy()+"_"+u.Host)
}

// ====== Helpers de cookies ====== //

type Cookies struct {
	Items    []*Cookie `json:"items"`
	Expire   int64     `json:"expire"`
	CachedAt string    `json:"cachedAt,omitempty"`
	Host     string    `json:"host,omitempty"`
	SiteURL  string    `json:"siteUrl,omitempty"`
}

type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  int64  `json:"expires"` // epoch seconds (0 = sessão)
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"sameSite"`
}

func (c *Cookies) toString() string {
	var parts []string
	for _, it := range c.Items {
		parts = append(parts, fmt.Sprintf("%s=%s", it.Name, it.Value))
	}
	return strings.Join(parts, "; ")
}

func (c *Cookies) getExpire() int64 { return c.Expire }

// func (c *Cookies) isExpired() bool {
// 	return time.Now().Unix() >= (c.Expire - 30)
// }

func (c *Cookies) isExpiredWithSkew(skew int64) bool {
	return time.Now().Unix() >= (c.Expire - skew)
}

// hasAuthCookies verifica se temos cookies típicas de auth SPO (FedAuth, rtFa, SPOIDCRL)
func hasAuthCookies(cs []*network.Cookie) bool {
	for _, c := range cs {
		n := strings.ToLower(c.Name)
		if n == "fedauth" || n == "rtfa" || n == "spoidcrl" {
			return true
		}
	}
	return false
}

// filterForHost filtra cookies para corresponderem ao domínio do site alvo.
func filterForHost(cs []*network.Cookie, host string) []*network.Cookie {
	host = strings.ToLower(host)
	var out []*network.Cookie
	for _, c := range cs {
		d := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if d == host || strings.HasSuffix(host, "."+d) {
			out = append(out, c)
		}
	}
	return out
}

// cookiesFromChromedp define Expire global, etc.
// Nota: os metadados Host/SiteURL/CachedAt são preenchidos depois
// em GetAuth()/cacheCookieToDisk.
func cookiesFromChromedp(_ string, cs []*network.Cookie) *Cookies {
	items := make([]*Cookie, 0, len(cs))
	now := time.Now().Unix()

	// 1) recolher expiries das cookies de auth
	var authExp []int64
	for _, c := range cs {
		n := strings.ToLower(c.Name)
		if n == "fedauth" || n == "rtfa" || n == "spoidcrl" {
			if c.Expires > 0 {
				authExp = append(authExp, int64(c.Expires))
			} else {
				// sessão: ~30 min por segurança
				authExp = append(authExp, now+1800)
			}
		}
	}

	// 2) escolher expiração global
	var chosenExp int64 = 0
	if len(authExp) > 0 {
		chosenExp = authExp[0]
		for _, e := range authExp[1:] {
			if e < chosenExp {
				chosenExp = e
			}
		}
	} else {
		for _, c := range cs {
			var e int64
			if c.Expires > 0 {
				e = int64(c.Expires)
			} else {
				e = now + 1800
			}
			if e > chosenExp {
				chosenExp = e
			}
		}
		if chosenExp == 0 {
			chosenExp = now + 1800
		}
	}

	// 3) serializar todas as cookies individuais
	for _, c := range cs {
		exp := int64(0)
		if c.Expires > 0 {
			exp = int64(c.Expires)
		}
		items = append(items, &Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  exp,
			HTTPOnly: c.HTTPOnly,
			Secure:   c.Secure,
			SameSite: c.SameSite.String(),
		})
	}

	return &Cookies{
		Items:  items,
		Expire: chosenExp,
	}
}
