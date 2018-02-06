package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/gorilla/mux"
	"github.com/govau/cf-common/env"
	"github.com/govau/cf-common/uaa"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"

	uuid "github.com/satori/go.uuid"
)

type GrafanaFilteringProxy struct {
	GrafanaURL      *url.URL
	GrafanaUsername string
	GrafanaPassword string

	Dashboards []string
	Orgs       []string

	cookieJarLock sync.Mutex
	cookieJar     *cookiejar.Jar

	applicationIDLock    sync.RWMutex
	applicationIDToSpace map[string]string
}

type contextKey string

var (
	SpaceKey = contextKey("verified-space")
)

func (gp *GrafanaFilteringProxy) allowedSpace(req *http.Request) string {
	verifiedSpace, ok := req.Context().Value(SpaceKey).(string)
	if !ok {
		return ""
	}
	return verifiedSpace
}

func (gp *GrafanaFilteringProxy) makeRequest(req *http.Request, w http.ResponseWriter, authenticated bool, filter func(io.Writer, io.Reader) error) {
	if authenticated {
		cj, err := gp.cookies()
		if err == nil {
			for _, cookie := range cj.Cookies(gp.GrafanaURL) {
				req.AddCookie(cookie)
			}
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	if filter == nil {
		io.Copy(w, resp.Body)
	} else {
		filter(w, resp.Body)
	}
}

func (gp *GrafanaFilteringProxy) makeUnauthenticatedRequest(req *http.Request, w http.ResponseWriter) {
	gp.makeRequest(req, w, false, nil)
}

func (gp *GrafanaFilteringProxy) makeAuthenticatedPrivilegedRequest(req *http.Request, w http.ResponseWriter) {
	gp.makeRequest(req, w, true, nil)
}

func (gp *GrafanaFilteringProxy) makeAuthenticatedPrivilegedRequestWithFilter(req *http.Request, w http.ResponseWriter, filter func(io.Writer, io.Reader) error) {
	gp.makeRequest(req, w, true, filter)
}

func (gp *GrafanaFilteringProxy) fetchQueryRange(w http.ResponseWriter, r *http.Request) {
	verifiedSpace := gp.allowedSpace(r)
	if verifiedSpace == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	filteredQuery, err := (&PromQueryFilterer{
		FilterFunc: func(name string, lm []*labels.Matcher) (map[string]string, error) {
			switch name {
			case "cf_application_info",
				"cf_application_instances_running",
				"cf_application_instances":
				return map[string]string{
					"space_id": verifiedSpace,
				}, nil
			case "firehose_container_metric_cpu_percentage",
				"firehose_container_metric_memory_bytes",
				"firehose_container_metric_memory_bytes_quota",
				"firehose_container_metric_disk_bytes",
				"firehose_container_metric_disk_bytes_quota",
				"firehose_http_start_stop_client_request_duration_seconds",
				"firehose_http_start_stop_client_request_duration_seconds_sum",
				"firehose_http_start_stop_client_request_duration_seconds_count",
				"firehose_http_start_stop_server_request_duration_seconds_count",
				"firehose_http_start_stop_server_request_duration_seconds_sum",
				"firehose_http_start_stop_server_request_duration_seconds",
				"firehose_http_start_stop_requests",
				"firehose_http_start_stop_response_size_bytes_sum",
				"firehose_http_start_stop_response_size_bytes",
				"firehose_http_start_stop_response_size_bytes_count":
				// TODO - build BI that is a map of application id to space, then if there's a plausible match, add it.

				// Find the application ID in question.
				appID := ""
				for _, l := range lm {
					if l.Name == "application_id" {
						appID = l.Value
						break
					}
				}

				gp.applicationIDLock.RLock()
				spaceForAppID := gp.applicationIDToSpace[appID]
				gp.applicationIDLock.RUnlock()

				if spaceForAppID != verifiedSpace {
					return nil, errors.New("application id not recognized as belonging to a space the user has access to")
				}

				return map[string]string{
					"application_id": appID, // this will make an equality operation, rather than the fuzzy regex stuff.
				}, nil
			default:
				return nil, errors.New("wrong vector")
			}
		},
	}).Filter(r.FormValue("query"))
	if err != nil {
		log.Println(err)
		log.Println(r.FormValue("query"))
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u := *gp.GrafanaURL
	u.Path = "/api/datasources/proxy/1/api/v1/query_range"
	u.RawQuery = (url.Values{
		"query": []string{filteredQuery},
		"step":  []string{r.FormValue("step")},
		"start": []string{r.FormValue("start")},
		"end":   []string{r.FormValue("end")},
	}).Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	gp.makeAuthenticatedPrivilegedRequest(req, w)
}

func (gp *GrafanaFilteringProxy) fetchSeries(w http.ResponseWriter, r *http.Request) {
	verifiedSpace := gp.allowedSpace(r)
	if verifiedSpace == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	filteredMatch, err := (&PromQueryFilterer{
		FilterFunc: func(name string, lm []*labels.Matcher) (map[string]string, error) {
			if name != "cf_application_info" {
				return nil, errors.New("wrong vector")
			}
			return map[string]string{
				"space_id": verifiedSpace,
			}, nil
		},
	}).Filter(r.FormValue("match[]"))
	if err != nil {
		log.Println(err)
		log.Println(r.FormValue("match[]"))
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u := *gp.GrafanaURL
	u.Path = "/api/datasources/proxy/1/api/v1/series"
	u.RawQuery = (url.Values{
		"match[]": []string{filteredMatch},
		"start":   []string{r.FormValue("start")},
		"end":     []string{r.FormValue("end")},
	}).Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	gp.makeAuthenticatedPrivilegedRequestWithFilter(req, w, func(out io.Writer, in io.Reader) error {
		var data struct {
			Status string              `json:"status"`
			Data   []map[string]string `json:"data"`
		}
		err := json.NewDecoder(in).Decode(&data)
		if err != nil {
			return err
		}

		// Siphon this info off, as we'll need later.
		gp.applicationIDLock.Lock()
		for _, ai := range data.Data {
			gp.applicationIDToSpace[ai["application_id"]] = ai["space_id"]
		}
		gp.applicationIDLock.Unlock()

		return json.NewEncoder(w).Encode(&data)
	})
}

func (gp *GrafanaFilteringProxy) proxyPublicGet(w http.ResponseWriter, r *http.Request) {
	verifiedSpace := gp.allowedSpace(r)
	if verifiedSpace == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u := *gp.GrafanaURL
	u.Path = r.URL.Path[len(fmt.Sprintf("/space/%s", html.EscapeString(verifiedSpace))):]

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	gp.makeUnauthenticatedRequest(req, w)
}

func (gp *GrafanaFilteringProxy) proxyDashboard(w http.ResponseWriter, r *http.Request) {
	verifiedSpace := gp.allowedSpace(r)
	if verifiedSpace == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	desiredDashboard := mux.Vars(r)["dashboard"]
	found := false
	for _, t := range gp.Dashboards {
		if t == desiredDashboard {
			found = true
			break
		}
	}
	if !found {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	desiredOrg := r.FormValue("orgId")
	if desiredOrg != "" {
		found = false
		for _, t := range gp.Orgs {
			if t == desiredOrg {
				found = true
				break
			}
		}
		if !found {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	refresh := r.FormValue("refresh")

	u := *gp.GrafanaURL
	u.Path = fmt.Sprintf("/dashboard/file/%s.json", url.PathEscape(desiredDashboard))
	u.RawQuery = (url.Values{
		"orgId":   []string{desiredOrg},
		"refresh": []string{refresh},
	}).Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	gp.makeAuthenticatedPrivilegedRequestWithFilter(req, w, func(out io.Writer, in io.Reader) error {
		buf := &bytes.Buffer{}
		_, err := io.Copy(buf, in)
		if err != nil {
			return err
		}

		_, err = out.Write([]byte(strings.Replace(string(buf.Bytes()), `<base href="/" />`, fmt.Sprintf(`<base href="/space/%s/" />`, html.EscapeString(verifiedSpace)), -1)))
		return err
	})
}

func (gp *GrafanaFilteringProxy) apiSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]struct {
		ID      int      `json:"id"`
		Starred bool     `json:"isStarred"`
		Tags    []string `json:"tags"`
		Title   string   `json:"title"`
		Type    string   `json:"dash-json"`
		URI     string   `json:"uri"`
	}{
		{
			Title: "Apps: Latency",
			Type:  "dash-json",
			URI:   "file/cf_apps_latency.json",
		},
		{
			Title: "Apps: Requests",
			Type:  "dash-json",
			URI:   "file/cf_apps_requests.json",
		},
		{
			Title: "Apps: System",
			Type:  "dash-json",
			URI:   "file/cf_apps_system.json",
		},
	})
}

func (gp *GrafanaFilteringProxy) proxyDashboardAPI(w http.ResponseWriter, r *http.Request) {
	desiredDashboard := mux.Vars(r)["dashboard"]
	found := false
	for _, t := range gp.Dashboards {
		if t == desiredDashboard {
			found = true
			break
		}
	}
	if !found {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u := *gp.GrafanaURL
	u.Path = fmt.Sprintf("/api/dashboards/file/%s.json", url.PathEscape(desiredDashboard))

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	gp.makeAuthenticatedPrivilegedRequest(req, w)
}

func (gp *GrafanaFilteringProxy) InitAndCreateHTTPHandler() http.Handler {
	gp.applicationIDToSpace = make(map[string]string)

	r := mux.NewRouter()
	r.PathPrefix("/space/{space_id}/public/").HandlerFunc(gp.proxyPublicGet)
	r.Path("/space/{space_id}/dashboard/file/{dashboard}.json").HandlerFunc(gp.proxyDashboard)
	r.Path("/space/{space_id}/api/dashboards/file/{dashboard}.json").HandlerFunc(gp.proxyDashboardAPI)
	r.Path("/space/{space_id}/api/datasources/proxy/1/api/v1/series").HandlerFunc(gp.fetchSeries)
	r.Path("/space/{space_id}/api/datasources/proxy/1/api/v1/query_range").HandlerFunc(gp.fetchQueryRange)
	r.Path("/space/{space_id}/api/search").HandlerFunc(gp.apiSearch)
	return r
}

func (gp *GrafanaFilteringProxy) cookies() (*cookiejar.Jar, error) {
	gp.cookieJarLock.Lock()
	defer gp.cookieJarLock.Unlock()

	if gp.cookieJar == nil {
		var err error
		gp.cookieJar, err = gp.login()
		if err != nil {
			return nil, err
		}
	}

	return gp.cookieJar, nil
}

func (gp *GrafanaFilteringProxy) login() (*cookiejar.Jar, error) {
	body, err := json.Marshal(struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Username string `json:"user"`
	}{
		Username: gp.GrafanaUsername,
		Password: gp.GrafanaPassword,
	})
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(gp.GrafanaURL.String()+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	ioutil.ReadAll(resp.Body) // we don't care about it, but Go seems to like us to fully read stuff for http keep-alive?
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code during auth")
	}

	rv, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	rv.SetCookies(gp.GrafanaURL, resp.Cookies())
	return rv, nil
}

func MustParseURL(s string) *url.URL {
	rv, err := url.Parse(s)
	if err != nil {
		log.Fatal(err)
	}
	return rv
}

type PromQueryFilterer struct {
	FilterFunc func(vector string, matches []*labels.Matcher) (map[string]string, error)
}

func (pqf *PromQueryFilterer) Filter(q string) (string, error) {
	expr, err := promql.ParseExpr(q)
	if err != nil {
		return "", err
	}

	newExpr, err := pqf.filterExpr(expr)
	if err != nil {
		return "", err
	}

	return newExpr.String(), nil
}

func (pqf *PromQueryFilterer) checkNameAndCreateMatchers(name string, inMatches []*labels.Matcher) ([]*labels.Matcher, error) {
	additionalFilters, err := pqf.FilterFunc(name, inMatches)
	if err != nil {
		return nil, err
	}

	var newLM []*labels.Matcher
	for _, lm := range inMatches {
		// don't add if in our required filters
		if additionalFilters[lm.Name] == "" {
			newLM = append(newLM, lm)
		}
	}
	for k, v := range additionalFilters {
		newLM = append(newLM, &labels.Matcher{
			Type:  labels.MatchEqual,
			Name:  k,
			Value: v,
		})
	}

	return newLM, nil
}

func (pqf *PromQueryFilterer) filterMatrixSelector(matrixExpr *promql.MatrixSelector) (promql.Expr, error) {
	newLM, err := pqf.checkNameAndCreateMatchers(matrixExpr.Name, matrixExpr.LabelMatchers)
	if err != nil {
		return nil, err
	}

	return &promql.MatrixSelector{
		Name:          matrixExpr.Name,
		Range:         matrixExpr.Range,
		Offset:        matrixExpr.Offset,
		LabelMatchers: newLM,
	}, nil
}

func (pqf *PromQueryFilterer) filterVectorSelector(vecExpr *promql.VectorSelector) (promql.Expr, error) {
	newLM, err := pqf.checkNameAndCreateMatchers(vecExpr.Name, vecExpr.LabelMatchers)
	if err != nil {
		return nil, err
	}

	return &promql.VectorSelector{
		Name:          vecExpr.Name,
		Offset:        vecExpr.Offset,
		LabelMatchers: newLM,
	}, nil
}

func (pqf *PromQueryFilterer) filterAgExpr(agExpr *promql.AggregateExpr) (promql.Expr, error) {
	if agExpr.Param != nil {
		return nil, errors.New("aggregate expression not understood (1)")
	}

	if agExpr.Without {
		return nil, errors.New("aggregate expression not understood (2)")
	}

	vecOrOther, err := pqf.filterExpr(agExpr.Expr)
	if err != nil {
		return nil, err
	}

	return &promql.AggregateExpr{
		Op:       agExpr.Op,
		Grouping: agExpr.Grouping,
		Expr:     vecOrOther,
	}, nil
}

var (
	emptyCard = &promql.VectorMatching{}
)

func (pqf *PromQueryFilterer) filterBinExpr(binExpr *promql.BinaryExpr) (promql.Expr, error) {
	if binExpr.VectorMatching != nil && !reflect.DeepEqual(binExpr.VectorMatching, emptyCard) {
		return nil, errors.New("too hard in expr")
	}

	newLeft, err := pqf.filterExpr(binExpr.LHS)
	if err != nil {
		return nil, err
	}

	newRight, err := pqf.filterExpr(binExpr.RHS)
	if err != nil {
		return nil, err
	}

	return &promql.BinaryExpr{
		Op:         binExpr.Op,
		LHS:        newLeft,
		RHS:        newRight,
		ReturnBool: binExpr.ReturnBool,
	}, nil
}

func (pqf *PromQueryFilterer) filterCall(call *promql.Call) (promql.Expr, error) {
	var newExpr []promql.Expr
	for _, e := range call.Args {
		n, err := pqf.filterExpr(e)
		if err != nil {
			return nil, err
		}
		newExpr = append(newExpr, n)
	}

	return &promql.Call{
		Func: call.Func,
		Args: newExpr,
	}, nil
}

func (pqf *PromQueryFilterer) filterExpr(expr promql.Expr) (promql.Expr, error) {
	switch n := expr.(type) {
	case *promql.VectorSelector:
		return pqf.filterVectorSelector(n)

	case *promql.MatrixSelector:
		return pqf.filterMatrixSelector(n)

	case *promql.BinaryExpr:
		return pqf.filterBinExpr(n)

	case *promql.AggregateExpr:
		return pqf.filterAgExpr(n)

	case *promql.Call:
		return pqf.filterCall(n)

	default:
		return nil, fmt.Errorf("unexpected type: %T", n)
	}
}

type VerifiedSpaceHandler struct {
	CFAPIURL string

	spaceUserLock  sync.Mutex
	spaceUserToTTL map[string]time.Time
}

func (vsh *VerifiedSpaceHandler) canUserAccess(user *uaa.LoggedInUser, spaceID string) bool {
	guid, err := uuid.FromString(spaceID)
	if err != nil {
		return false
	}

	keyInMap := fmt.Sprintf("%s|%s", guid.String(), user.EmailAddress)
	now := time.Now()

	vsh.spaceUserLock.Lock()
	defer vsh.spaceUserLock.Unlock()

	ttl, ok := vsh.spaceUserToTTL[keyInMap]
	if ok {
		if ttl.After(now) {
			return true
		}
		delete(vsh.spaceUserToTTL, keyInMap)
	}

	// Else, we'll figure it out the hard way.
	// Do this whole thing in the mutex as above. In theory we could lock per user (or even not at all) - we can optimize that later
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v2/spaces/%s/developers", vsh.CFAPIURL, guid.String()), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.AccessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var data struct {
		Resources []*struct {
			Entity struct {
				Username string
			}
		}
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return false
	}

	for _, r := range data.Resources {
		if r.Entity.Username == user.EmailAddress {
			vsh.spaceUserToTTL[keyInMap] = now.Add(time.Hour)
			return true
		}
	}

	return false
}

func (vsh *VerifiedSpaceHandler) Wrap(child http.Handler) http.Handler {
	vsh.spaceUserToTTL = make(map[string]time.Time)
	r := mux.NewRouter()
	r.PathPrefix("/space/{space_id}").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		desiredSpaceID := mux.Vars(r)["space_id"]

		liu, ok := r.Context().Value(uaa.KeyLoggedInUser).(*uaa.LoggedInUser)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if !vsh.canUserAccess(liu, desiredSpaceID) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		child.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), SpaceKey, desiredSpaceID)))
	})
	return r
}

func main() {
	lookupPath := []env.VarSetOpt{env.WithOSLookup()}
	app, err := cfenv.Current()
	if err == nil {
		lookupPath = append(lookupPath, env.WithUPSLookup(app, "grafana-ups"))
	}
	envVars := env.NewVarSet(lookupPath...)

	csrfKey, err := hex.DecodeString(envVars.MustString("CSRF_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	if len(csrfKey) != 32 {
		log.Fatal("CSRF_KEY should be 32 hex-encoded bytes")
	}

	oauthBase := envVars.MustString("EXTERNAL_URL")
	if envVars.MustBool("INSECURE") {
		oauthBase = "http://localhost:8000"
	}

	uaaURL := envVars.MustString("UAA_URL")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", envVars.MustString("PORT")), (&uaa.LoginHandler{
		Cookies: uaa.MustCreateBasicCookieHandler(envVars.MustBool("INSECURE")),
		UAA: &uaa.Client{
			URL:          uaaURL,
			ClientID:     envVars.MustString("CLIENT_ID"),
			ClientSecret: envVars.MustString("CLIENT_SECRET"),
			ExternalURL:  uaaURL,
		},
		ExternalUAAURL: uaaURL,
		Scopes: []string{
			"openid",
			"cloud_controller.read",
		},
		BaseURL:       oauthBase,
		DeniedContent: []byte("denied"),
		ShouldIgnore: func(r *http.Request) bool {
			if r.URL.Path == "/favicon.ico" {
				return true // no auth here (if we do, we get a race condition)
			}
			return false
		},
	}).Wrap((&VerifiedSpaceHandler{
		CFAPIURL: envVars.MustString("CF_API_URL"),
	}).Wrap((&GrafanaFilteringProxy{
		GrafanaURL:      MustParseURL(envVars.MustString("GRAFANA_URL")),
		GrafanaUsername: (envVars.MustString("GRAFANA_USERNAME")),
		GrafanaPassword: (envVars.MustString("GRAFANA_PASSWORD")),
		Dashboards: []string{
			"cf_apps_system",
			"cf_apps_latency",
			"cf_apps_requests",
		},
		Orgs: []string{
			"1",
		},
	}).InitAndCreateHTTPHandler()))))
}
