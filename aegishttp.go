package caddy_aegis

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&AegisHttp{})
	httpcaddyfile.RegisterHandlerDirective("aegis_http", parseCaddyfile)
}

// AegisHttp is a Caddy V2 middleware that provides Zero Trust E2E Encryption
type AegisHttp struct {
	ChallengePath        string `json:"challenge_path,omitempty"`
	LoginPath            string `json:"login_path,omitempty"`
	ServerEmail          string `json:"server_email,omitempty"`
	ServerPassphrase     string `json:"server_passphrase,omitempty"`
	ServerPrivateKeyPath string `json:"server_private_key_path,omitempty"`
	ServerPublicKeyPath  string `json:"server_public_key_path,omitempty"`
	DecryptRequests      bool   `json:"decrypt_requests,omitempty"`
	EncryptResponses     bool   `json:"encrypt_responses,omitempty"`
	RequireKeyserver     bool   `json:"require_keyserver,omitempty"`
	CheckRevocation      bool   `json:"check_revocation,omitempty"`
	MinApproveCount      int    `json:"min_approve_count,omitempty"`
	TunnelingEnabled     bool   `json:"tunneling_enabled,omitempty"`
	AllowedKeysApi       string `json:"allowed_keys_api,omitempty"`

	// internal state
	serverEntity     *openpgp.Entity
	activeChallenges map[string]bool
	publicKeyCache   map[string]pubKeyCacheEntry
	activeMux        sync.RWMutex
	cacheMux         sync.RWMutex
	logger           *zap.Logger
}

type pubKeyCacheEntry struct {
	EntityList openpgp.EntityList
	ExpiresAt  time.Time
}

type LoginRequest struct {
	Email     string `json:"email"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

var (
	nonceCache   sync.Map
	nonceCleanup sync.Once

	_ caddy.Provisioner           = (*AegisHttp)(nil)
	_ caddy.Validator             = (*AegisHttp)(nil)
	_ caddyhttp.MiddlewareHandler = (*AegisHttp)(nil)
	_ caddyfile.Unmarshaler       = (*AegisHttp)(nil)
)

// CaddyModule returns the Caddy module information.
func (*AegisHttp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.aegis_http",
		New: func() caddy.Module { return new(AegisHttp) },
	}
}

// Provision sets up the module parameters.
func (m *AegisHttp) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// Defaults
	if m.ChallengePath == "" {
		m.ChallengePath = "/api/challenge"
	}
	if m.LoginPath == "" {
		m.LoginPath = "/api/login"
	}
	if m.ServerPrivateKeyPath == "" {
		m.ServerPrivateKeyPath = "server_private.asc"
	}
	if m.ServerPublicKeyPath == "" {
		m.ServerPublicKeyPath = "server_public.asc"
	}
	
	m.activeChallenges = make(map[string]bool)
	m.publicKeyCache = make(map[string]pubKeyCacheEntry)

	// Idempotency GC for replay attacks
	nonceCleanup.Do(func() {
		go func() {
			for {
				time.Sleep(1 * time.Minute)
				now := time.Now().UnixNano() / 1e6
				nonceCache.Range(func(key, value interface{}) bool {
					if now-value.(int64) > 60000 {
						nonceCache.Delete(key)
					}
					return true
				})
			}
		}()
	})

	if m.DecryptRequests {
		if m.ServerEmail == "" {
			return fmt.Errorf("DecryptRequests is true but ServerEmail is empty")
		}
		if _, err := os.Stat(m.ServerPrivateKeyPath); os.IsNotExist(err) {
			m.logger.Info("Generating new Server GPG KeyPair...")
			if m.ServerPassphrase == "" {
				m.logger.Warn("ServerPassphrase is empty. Key will be unencrypted!")
			}
			entity, err := m.generateServerKey(m.ServerEmail, m.ServerPassphrase, m.ServerPrivateKeyPath, m.ServerPublicKeyPath)
			if err != nil {
				return err
			}
			m.serverEntity = entity
			m.logger.Info("GPG Keys generated. Uploading to Ubuntu keyserver...")
			if err := m.uploadKeyToKeyserver(entity); err != nil {
				m.logger.Warn("Failed to upload to keyserver", zap.Error(err))
			}
		} else {
			m.logger.Info("Loading existing Server GPG KeyPair", zap.String("path", m.ServerPrivateKeyPath))
			entity, err := m.loadServerKey(m.ServerPassphrase, m.ServerPrivateKeyPath)
			if err != nil {
				return err
			}
			m.serverEntity = entity
		}
	}

	return nil
}

// Validate checks the module settings.
func (m *AegisHttp) Validate() error {
	return nil
}

// parseCaddyfile unmarshals tokens from the Caddyfile configuration into a new struct.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m AegisHttp
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (m *AegisHttp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "challenge_path":
				if !d.Args(&m.ChallengePath) {
					return d.ArgErr()
				}
			case "login_path":
				if !d.Args(&m.LoginPath) {
					return d.ArgErr()
				}
			case "server_email":
				if !d.Args(&m.ServerEmail) {
					return d.ArgErr()
				}
			case "server_passphrase":
				if !d.Args(&m.ServerPassphrase) {
					return d.ArgErr()
				}
			case "server_private_key_path":
				if !d.Args(&m.ServerPrivateKeyPath) {
					return d.ArgErr()
				}
			case "server_public_key_path":
				if !d.Args(&m.ServerPublicKeyPath) {
					return d.ArgErr()
				}
			case "decrypt_requests":
				m.DecryptRequests = true
			case "encrypt_responses":
				m.EncryptResponses = true
			case "require_keyserver":
				m.RequireKeyserver = true
			case "check_revocation":
				m.CheckRevocation = true
			case "tunneling_enabled":
				m.TunnelingEnabled = true
			case "allowed_keys_api":
				if !d.Args(&m.AllowedKeysApi) {
					return d.ArgErr()
				}
			}
		}
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (m *AegisHttp) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Server Public Key Publisher
	if r.URL.Path == "/api/server-pubkey" && r.Method == http.MethodGet && m.DecryptRequests {
		buf := new(bytes.Buffer)
		wr, _ := armor.Encode(buf, openpgp.PublicKeyType, nil)
		m.serverEntity.Serialize(wr)
		wr.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("x-gpg-server-id", m.ServerEmail)
		w.Write(buf.Bytes())
		return nil
	}

	// Inject support flags
	r.Header.Set("x-gpg-support", "true")
	w.Header().Set("x-gpg-support", "true")
	if m.DecryptRequests && m.ServerEmail != "" {
		r.Header.Set("x-gpg-server-id", m.ServerEmail)
		w.Header().Set("x-gpg-server-id", m.ServerEmail)
	}
	if m.TunnelingEnabled {
		w.Header().Set("x-gpg-tunneling", "true")
	} else {
		w.Header().Set("x-gpg-tunneling", "false")
	}

	// Decrypt Incoming Requests
	if m.DecryptRequests && r.Header.Get("x-gpg-encrypted") != "" {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			block, err := armor.Decode(bytes.NewReader(body))
			if err == nil && block.Type == "PGP MESSAGE" {
				md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{m.serverEntity}, nil, nil)
				if err == nil {
					decryptedBody, err := io.ReadAll(md.UnverifiedBody)
					if err == nil {
						var parsed map[string]interface{}
						if errUnmarshal := json.Unmarshal(decryptedBody, &parsed); errUnmarshal == nil {
							if tsVal, ok := parsed["_gpg_timestamp"].(float64); ok {
								if nonce, ok := parsed["_gpg_nonce"].(string); ok {
									now := float64(time.Now().UnixNano()) / 1e6
									if now-tsVal > 60000 || tsVal-now > 60000 {
										return m.jsonError(w, 403, "Payload expired or timestamp invalid. Replay Attack Prevented.")
									}
									if _, loaded := nonceCache.LoadOrStore(nonce, int64(now)); loaded {
										return m.jsonError(w, 403, "Duplicate payload detected. Replay Attack Prevented.")
									}
									delete(parsed, "_gpg_timestamp")
									delete(parsed, "_gpg_nonce")
									decryptedBody, _ = json.Marshal(parsed)
								}
							}
						}

						if r.Header.Get("x-gpg-tunnel") == "true" {
							var tunnel struct {
								Method  string            `json:"tunnel_method"`
								Url     string            `json:"tunnel_url"`
								Headers map[string]string `json:"tunnel_headers"`
								Body    interface{}       `json:"tunnel_body"`
							}
							if json.Unmarshal(decryptedBody, &tunnel) == nil {
								r.Method = tunnel.Method
								parsedURL, _ := url.Parse(tunnel.Url)
								r.URL = parsedURL
								for k, v := range tunnel.Headers {
									r.Header.Set(k, v)
								}
								if tunnel.Body != nil {
									bodyBytes, _ := json.Marshal(tunnel.Body)
									r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
									r.ContentLength = int64(len(bodyBytes))
								} else {
									r.Body = io.NopCloser(bytes.NewReader([]byte{}))
									r.ContentLength = 0
								}
							}
						} else {
							r.Body = io.NopCloser(bytes.NewReader(decryptedBody))
							r.ContentLength = int64(len(decryptedBody))
						}
					}
				} else {
					return m.jsonError(w, 400, "Failed to decrypt client payload: "+err.Error())
				}
			}
		}
	}

	// Challenge Route
	if r.URL.Path == m.ChallengePath && r.Method == http.MethodGet {
		challenge := m.generateChallenge()
		m.activeMux.Lock()
		m.activeChallenges[challenge] = true
		m.activeMux.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"challenge": challenge})
		return nil
	}

	// Login Route
	if r.URL.Path == m.LoginPath && r.Method == http.MethodPost {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return m.jsonError(w, 400, "Invalid request payload")
		}

		m.activeMux.RLock()
		isValid := m.activeChallenges[req.Challenge]
		m.activeMux.RUnlock()

		if !isValid {
			return m.jsonError(w, 400, "Invalid or expired challenge")
		}

		block, _ := clearsign.Decode([]byte(req.Signature))
		if block == nil {
			return m.jsonError(w, 400, "Failed to decode clear signature")
		}
		if string(block.Bytes) != req.Challenge {
			return m.jsonError(w, 400, "Signature does not cover the exact challenge string")
		}

		var keyring openpgp.EntityList
		var err error

		m.cacheMux.RLock()
		cached, ok := m.publicKeyCache[req.Email]
		m.cacheMux.RUnlock()

		if ok && time.Now().Before(cached.ExpiresAt) {
			keyring = cached.EntityList
		} else if m.RequireKeyserver {
			keyring, err = m.fetchFromWKD(req.Email)
			if err != nil || len(keyring) == 0 {
				keyserverURL := "http://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=" + url.QueryEscape(req.Email)
				resp, errHttp := http.Get(keyserverURL)
				if errHttp != nil {
					return m.jsonError(w, 500, "Failed to connect to keyserver")
				}
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					keyring, err = openpgp.ReadArmoredKeyRing(resp.Body)
				}
			}
		} else {
			keyring, err = openpgp.ReadArmoredKeyRing(bytes.NewBufferString(req.PublicKey))
		}

		if err != nil || len(keyring) == 0 {
			return m.jsonError(w, 400, "Failed to load public keys (ensure your key is published to keyserver or passed)")
		}

		signer, err := openpgp.CheckDetachedSignature(keyring, bytes.NewBuffer(block.Bytes), block.ArmoredSignature.Body, nil)
		if err != nil {
			return m.jsonError(w, 401, "Invalid signature: "+err.Error())
		}

		emailMatched := false
		var matchedIdentity *openpgp.Identity
		for _, ident := range signer.Identities {
			if ident.UserId.Email == req.Email {
				emailMatched = true
				matchedIdentity = ident
				break
			}
		}
		if !emailMatched {
			return m.jsonError(w, 401, "Signature valid, but email does not match the key identity")
		}
		if m.CheckRevocation && len(signer.Revocations) > 0 {
			return m.jsonError(w, 401, "The GPG key has been revoked by the owner.")
		}
		if m.MinApproveCount > 0 {
			approveCount := 0
			for _, sig := range matchedIdentity.Signatures {
				if sig.IssuerKeyId != nil && *sig.IssuerKeyId != signer.PrimaryKey.KeyId {
					approveCount++
				}
			}
			if approveCount < m.MinApproveCount {
				return m.jsonError(w, 401, "GPG key lacks sufficient Web of Trust approvals")
			}
		}

		if m.AllowedKeysApi != "" {
			fingerprint := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
			apiURL := strings.TrimRight(m.AllowedKeysApi, "/") + "/" + fingerprint
			client := &http.Client{Timeout: 5 * time.Second}
			
			resp, errAPI := client.Get(apiURL)
			if errAPI != nil || resp.StatusCode != http.StatusOK {
				return m.jsonError(w, 401, "Failed to verify key authorization")
			}
			defer resp.Body.Close()
			
			var allowedResp struct {
				Allowed bool `json:"allowed"`
			}
			if errDecode := json.NewDecoder(resp.Body).Decode(&allowedResp); errDecode != nil {
				return m.jsonError(w, 500, "Invalid response from allowed keys API")
			}
			if !allowedResp.Allowed {
				return m.jsonError(w, 401, "This GPG key is not authorized to login")
			}
		}

		m.activeMux.Lock()
		delete(m.activeChallenges, req.Challenge)
		m.activeMux.Unlock()

		m.cacheMux.Lock()
		m.publicKeyCache[req.Email] = pubKeyCacheEntry{
			EntityList: openpgp.EntityList{signer},
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		}
		m.cacheMux.Unlock()

		// Generate secure session token to prevent XSS decryption oracles
		tokenBytes := make([]byte, 16)
		rand.Read(tokenBytes)
		sessionToken := hex.EncodeToString(tokenBytes)

		// Set Context and Payload Response
		w.Header().Set("x-gpg-session-token", sessionToken)
		w.Header().Set("Access-Control-Expose-Headers", "x-gpg-session-token, x-gpg-server-id, x-gpg-support, x-gpg-encrypted")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":       "success",
			"message":      "Successfully authenticated via GPG Aegis Http!",
			"email":        req.Email,
			"sessionToken": sessionToken,
		})
		return nil
	}

	// Encrypt Responses Wrap
	if m.EncryptResponses {
		gpgID := r.Header.Get("x-gpg-id")
		if gpgID != "" {
			m.cacheMux.RLock()
			cached, ok := m.publicKeyCache[gpgID]
			m.cacheMux.RUnlock()

			if ok && time.Now().Before(cached.ExpiresAt) {
				recorder := caddyhttp.NewResponseRecorder(w, new(bytes.Buffer), func(status int, header http.Header) bool {
					return true // Always buffer the response for encryption
				})
				
				err := next.ServeHTTP(recorder, r)
				if err != nil {
					return err
				}

				status := recorder.Status()
				if status == 0 {
					status = 200
				}

				if status < 200 || status >= 400 {
					recorder.WriteResponse()
					return nil
				}

				encryptBuf := new(bytes.Buffer)
				armoredWriter, err := armor.Encode(encryptBuf, "PGP MESSAGE", nil)
				if err == nil {
					plaintextWriter, err := openpgp.Encrypt(armoredWriter, cached.EntityList, nil, nil, nil)
					if err == nil {
						plaintextWriter.Write(recorder.Buffer().Bytes())
						plaintextWriter.Close()
						armoredWriter.Close()

						// Write encrypted back
						w.Header().Set("x-gpg-encrypted", "true")
						w.Header().Del("Content-Length")
						w.WriteHeader(status)
						w.Write(encryptBuf.Bytes())
						return nil
					} else {
						fmt.Printf("AegisHttp: PGP Encrypt Error: %v\n", err)
					}
				} else {
					fmt.Printf("AegisHttp: Armor Encode Error: %v\n", err)
				}
				// Default back to plain if encryption fails
				return m.jsonError(w, 500, "Server failed to encrypt outgoing response securely")
			} else {
				return m.jsonError(w, 401, "GPG Session expired or invalid. Please login again.")
			}
		}
	}

	return next.ServeHTTP(w, r)
}

func (m *AegisHttp) jsonError(w http.ResponseWriter, code int, msg string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
	return nil
}

func (m *AegisHttp) generateChallenge() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *AegisHttp) zbase32Encode(data []byte) string {
	alphabet := "ybndrfg8ejkmcpqxot1uwisza345h769"
	var bits string
	for _, b := range data {
		bits += fmt.Sprintf("%08b", b)
	}
	var encoded string
	for i := 0; i < len(bits); i += 5 {
		chunk := bits[i:]
		if len(chunk) > 5 {
			chunk = chunk[:5]
		} else {
			for len(chunk) < 5 {
				chunk += "0"
			}
		}
		num, _ := strconv.ParseInt(chunk, 2, 64)
		encoded += string(alphabet[num])
	}
	return encoded
}

func (m *AegisHttp) fetchFromWKD(email string) (openpgp.EntityList, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email")
	}
	localPart := strings.ToLower(parts[0])
	domain := strings.ToLower(parts[1])

	h := sha1.New()
	h.Write([]byte(localPart))
	hash := m.zbase32Encode(h.Sum(nil))

	url := fmt.Sprintf("https://%s/.well-known/openpgpkey/hu/%s?l=%s", domain, hash, localPart)
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WKD not found")
	}

	return openpgp.ReadKeyRing(resp.Body)
}

func (m *AegisHttp) generateServerKey(email, passphrase, privPath, pubPath string) (*openpgp.Entity, error) {
	config := &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
	entity, err := openpgp.NewEntity("Aegis Http Server", "Backend API", email, config)
	if err != nil {
		return nil, err
	}

	if passphrase != "" {
		if err := entity.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
			return nil, err
		}
		for _, subkey := range entity.Subkeys {
			if err := subkey.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
				return nil, err
			}
		}
	}

	privFile, err := os.Create(privPath)
	if err == nil {
		defer privFile.Close()
		w, _ := armor.Encode(privFile, openpgp.PrivateKeyType, nil)
		entity.SerializePrivateWithoutSigning(w, config)
		w.Close()
	}

	pubFile, err := os.Create(pubPath)
	if err == nil {
		defer pubFile.Close()
		w, _ := armor.Encode(pubFile, openpgp.PublicKeyType, nil)
		entity.Serialize(w)
		w.Close()
	}

	return entity, nil
}

func (m *AegisHttp) loadServerKey(passphrase, privPath string) (*openpgp.Entity, error) {
	f, err := os.Open(privPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil || len(entityList) == 0 {
		return nil, fmt.Errorf("failed to read server private key")
	}
	entity := entityList[0]

	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if passphrase == "" {
			return nil, fmt.Errorf("server key is encrypted but no passphrase provided")
		}
		if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
			return nil, err
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
				subkey.PrivateKey.Decrypt([]byte(passphrase))
			}
		}
	}

	return entity, nil
}

func (m *AegisHttp) uploadKeyToKeyserver(entity *openpgp.Entity) error {
	buf := new(bytes.Buffer)
	w, _ := armor.Encode(buf, openpgp.PublicKeyType, nil)
	entity.Serialize(w)
	w.Close()

	data := url.Values{}
	data.Set("keytext", buf.String())

	resp, err := http.PostForm("http://keyserver.ubuntu.com/pks/add", data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keyserver returned status: %d", resp.StatusCode)
	}

	return nil
}
