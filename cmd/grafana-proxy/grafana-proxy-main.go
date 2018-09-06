package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"strconv"
	"strings"
	"sync"
	"time"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
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

	Dashboards map[string]string
	Orgs       []string

	cookieJarLock sync.Mutex
	cookieJar     *cookiejar.Jar
	cookieJarTTL  time.Time

	applicationIDLock    sync.RWMutex
	applicationIDToSpace map[string]string
}

var (
	singleBlackPixel = func(s string) []byte {
		rv, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return rv
	}(`iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNiOAMAANUAz5n+TlUAAAAASUVORK5CYII=`)
)

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

// w can be nil
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
		if w != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()

	if w != nil {
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
	}
	if filter == nil {
		if w != nil {
			io.Copy(w, resp.Body)
		}
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
	proxyIDNumber, err := strconv.Atoi(mux.Vars(r)["proxy_id"])
	if err != nil {
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

				spaceForAppID, err := gp.getSpaceForApp(appID, proxyIDNumber)
				if err != nil {
					return nil, err
				}

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
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u := *gp.GrafanaURL
	u.Path = "/api/datasources/proxy/3/api/v1/query_range"
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
	proxyIDNumber, err := strconv.Atoi(mux.Vars(r)["proxy_id"])
	if err != nil {
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
	u.Path = fmt.Sprintf("/api/datasources/proxy/%d/api/v1/series", proxyIDNumber)
	u.RawQuery = (url.Values{
		"match[]": []string{filteredMatch},
		"start":   []string{r.FormValue("start")},
		"end":     []string{r.FormValue("end")},
	}).Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	gp.makeAuthenticatedPrivilegedRequestWithFilter(req, w, gp.saveSpaceIDsForApps)
}

func (gp *GrafanaFilteringProxy) getSpaceForApp(appID string, proxyIDNumber int) (string, error) {
	for attempt := 0; ; attempt++ {
		gp.applicationIDLock.RLock()
		spaceForAppID := gp.applicationIDToSpace[appID]
		gp.applicationIDLock.RUnlock()

		if spaceForAppID != "" {
			return spaceForAppID, nil
		}

		if attempt > 1 {
			return "", errors.New("no space found")
		}

		// Else, let's see if we can look it up.
		u := *gp.GrafanaURL
		u.Path = fmt.Sprintf("/api/datasources/proxy/%d/api/v1/series", proxyIDNumber)
		u.RawQuery = (url.Values{
			"match[]": []string{(&promql.VectorSelector{
				Name: "cf_application_info",
				LabelMatchers: []*labels.Matcher{
					&labels.Matcher{
						Name:  "application_id",
						Type:  labels.MatchEqual,
						Value: appID,
					},
				},
			}).String()},
		}).Encode()

		req, err := http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}

		gp.makeAuthenticatedPrivilegedRequestWithFilter(req, nil, gp.saveSpaceIDsForApps)
	}

}

// out can be nil
func (gp *GrafanaFilteringProxy) saveSpaceIDsForApps(out io.Writer, in io.Reader) error {
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

	if out == nil {
		return nil
	}

	return json.NewEncoder(out).Encode(&data)
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
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Since the user controls the path, this *must* be unauthenticated. Consider implementing whitelist of allowed paths
	gp.makeUnauthenticatedRequest(req, w)
}

func (gp *GrafanaFilteringProxy) proxyDashboard(w http.ResponseWriter, r *http.Request) {
	verifiedSpace := gp.allowedSpace(r)
	if verifiedSpace == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	desiredDashboard := mux.Vars(r)["dashboard"]
	shortName, found := gp.Dashboards[desiredDashboard]
	if !found {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if shortName != mux.Vars(r)["shortName"] {
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
	u.Path = fmt.Sprintf("/d/%s/%s", url.PathEscape(desiredDashboard), url.PathEscape(shortName))
	u.RawQuery = (url.Values{
		"orgId":   []string{desiredOrg},
		"refresh": []string{refresh},
	}).Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		log.Println(err)
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

func (gp *GrafanaFilteringProxy) apiAnnotations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]struct{}{})
}

func (gp *GrafanaFilteringProxy) tags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]struct{}{})
}

func (gp *GrafanaFilteringProxy) avatar(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Write(singleBlackPixel)
}

func (gp *GrafanaFilteringProxy) apiSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]struct {
		ID      int      `json:"id"`
		UID     string   `json:"uid"`
		Starred bool     `json:"isStarred"`
		Tags    []string `json:"tags"`
		Title   string   `json:"title"`
		Type    string   `json:"type"`
		URI     string   `json:"uri"`
		URL     string   `json:"url"`
	}{
		{
			UID:   "cf_apps_latency",
			Title: "Apps: Latency",
			Type:  "dash-db",
			Tags:  []string{"apps"},
			URI:   "../d/cf_apps_latency/apps-latency",
			URL:   "d/cf_apps_latency/apps-latency",
		},
		{
			UID:   "cf_apps_requests",
			Title: "Apps: Requests",
			Type:  "dash-db",
			Tags:  []string{"apps"},
			URI:   "../d/cf_apps_requests/apps-requests",
			URL:   "d/cf_apps_requests/apps-requests",
		},
		{
			UID:   "cf_apps_system",
			Title: "Apps: System",
			Type:  "dash-db",
			Tags:  []string{"apps"},
			URI:   "../d/cf_apps_system/apps-system",
			URL:   "d/cf_apps_system/apps-system",
		},
	})
}

func (gp *GrafanaFilteringProxy) proxyDashboardAPI(w http.ResponseWriter, r *http.Request) {
	desiredDashboard := mux.Vars(r)["dashboard"]
	_, found := gp.Dashboards[desiredDashboard]
	if !found {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	u := *gp.GrafanaURL
	u.Path = fmt.Sprintf("/api/dashboards/uid/%s", url.PathEscape(desiredDashboard))

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	gp.makeAuthenticatedPrivilegedRequest(req, w)
}

func (gp *GrafanaFilteringProxy) InitAndCreateHTTPHandler() http.Handler {
	gp.applicationIDToSpace = make(map[string]string)

	// TODO: figure out what proxy_id is

	r := mux.NewRouter()
	r.PathPrefix("/space/{space_id}/public/").HandlerFunc(gp.proxyPublicGet)
	r.Path("/space/{space_id}/d/{dashboard}/{shortName}").HandlerFunc(gp.proxyDashboard)
	r.Path("/space/{space_id}/api/dashboards/uid/{dashboard}").HandlerFunc(gp.proxyDashboardAPI)
	r.Path("/space/{space_id}/api/datasources/proxy/{proxy_id}/api/v1/series").HandlerFunc(gp.fetchSeries)
	r.Path("/space/{space_id}/api/datasources/proxy/{proxy_id}/api/v1/query_range").HandlerFunc(gp.fetchQueryRange)
	r.Path("/space/{space_id}/api/search").HandlerFunc(gp.apiSearch)
	r.Path("/space/{space_id}/api/annotations").HandlerFunc(gp.apiAnnotations)
	r.Path("/space/{space_id}/api/dashboards/tags").HandlerFunc(gp.tags)

	r.Path("/avatar/{ignore}").HandlerFunc(gp.avatar)
	return r
}

func (gp *GrafanaFilteringProxy) cookies() (*cookiejar.Jar, error) {
	gp.cookieJarLock.Lock()
	defer gp.cookieJarLock.Unlock()

	if gp.cookieJar == nil || time.Now().After(gp.cookieJarTTL) {
		var err error
		gp.cookieJar, err = gp.login()
		if err != nil {
			return nil, err
		}
		// apparently sessions last by default 86400 seconds - we'll discard after an hour
		gp.cookieJarTTL = time.Now().Add(time.Hour)
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
	CFAPIURL    string
	PassThrough []string

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
	for _, pt := range vsh.PassThrough {
		r.PathPrefix(pt).Handler(child)
	}
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

	cookieAuthKey, err := hex.DecodeString(envVars.MustString("COOKIE_AUTH_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	if len(cookieAuthKey) != 64 {
		log.Fatal("COOKIE_AUTH_KEY should be 64 hex-encoded bytes")
	}

	cookieEncKey, err := hex.DecodeString(envVars.MustString("COOKIE_ENCRYPTION_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	if len(cookieEncKey) != 32 {
		log.Fatal("COOKIE_ENCRYPTION_KEY should be 32 hex-encoded bytes")
	}

	cookieStore := sessions.NewCookieStore(cookieAuthKey, cookieEncKey)
	cookieStore.Options.HttpOnly = true
	cookieStore.Options.Secure = !envVars.MustBool("INSECURE_COOKIES")

	oauthBase := envVars.MustString("EXTERNAL_URL")

	uaaURL := envVars.MustString("UAA_URL")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", envVars.MustString("PORT")), (&uaa.LoginHandler{
		Cookies: cookieStore,
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
		CFAPIURL:    envVars.MustString("CF_API_URL"),
		PassThrough: []string{"/avatar/{ignore}"},
	}).Wrap((&GrafanaFilteringProxy{
		GrafanaURL:      MustParseURL(envVars.MustString("GRAFANA_URL")),
		GrafanaUsername: (envVars.MustString("GRAFANA_USERNAME")),
		GrafanaPassword: (envVars.MustString("GRAFANA_PASSWORD")),
		Dashboards: map[string]string{
			"cf_apps_system":   "apps-system",
			"cf_apps_latency":  "apps-latency",
			"cf_apps_requests": "apps-requests",
		},
		Orgs: []string{
			"1",
		},
	}).InitAndCreateHTTPHandler()))))
}
