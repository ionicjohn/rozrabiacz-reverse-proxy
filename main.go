package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
)

var config Config
var accounts []Account
var currentAccountIndex int = 0

type Config struct {
	BindAddress string `json:"bind"`
	UseHttp     bool   `json:"useHttp"`
    Strona        string `json:"strona"`
}

type Account struct {
	Session string `json:"session"`
	Mail    string `json:"mail"`
}

type SessionResponse struct {
	AccessToken    string `json:"accessToken"`
	ExpirationDate string `json:"expire"`
}

func rewriteJs(b []byte, host string) []byte {
	var protocol string
	if config.UseHttp {
		protocol = "http"
	} else {
		protocol = "https"
	}
	b = bytes.Replace(b, []byte("https://odrabiamy.pl"), []byte(protocol+"://"+host), -1)      // naprawienie przeroznych URL
	b = bytes.Replace(b, []byte("r.host=\"odrabiamy.pl\""), []byte("r.host=\""+host+"\""), -1) // naprawienie api v1.3 - hack!
	if config.UseHttp {                                                                        // naprawienie api v1.3 - hack 2 - zeby http bylo
		b = bytes.Replace(b, []byte("r.protocol=\"https\""), []byte("r.protocol=\"http\""), -1)
	}
	return b
}
func rewriteBody(resp *http.Response, host string) (err error) {
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = resp.Body.Close()
	if err != nil {
		return err
	}

        if resp.Request.URL.Path == "/api/v3/profile" {
               var profile interface{}
               json.Unmarshal(b, &profile)
               
    if m, ok := profile.(map[string]interface{}); ok {
        delete(m, "userOffences") // No problem if "foo" isn't in the map
    }

               b, _ = json.Marshal(profile)
        }

	if strings.HasSuffix(resp.Request.URL.Path, ".js") {
		b = rewriteJs(b, host)
	} else if resp.Request.URL.Path == "/api/auth/session" && resp.Request.Method == "GET" {
		var session SessionResponse
		json.Unmarshal(b, &session)

	//	session.AccessToken = base64.StdEncoding.EncodeToString(encrypt([]byte("jajcarz key 1234"), []byte(session.AccessToken)))
                	
        	b, _ = json.Marshal(session)
		delete(resp.Header, "Set-Cookie")
	} else if resp.Request.URL.Path == "/api/v3/user_books" && resp.Request.Method == "GET" {
		fmt.Printf("Używane konto: " + accounts[currentAccountIndex].Mail + "\n")
		fmt.Printf("Ładuje user_books...\n")
		b = []byte("{\"userBooks\":[{\"id\":21372137,\"bookId\":21372137,\"userId\":1838771,\"createdAt\":\"2022-09-22T20:29:34+02:00\",\"kind\":\"Informacja\",\"title\":\"discord.gg/zsl - support stronki\",\"reformLevel\":null,\"subject\":\"Discord\",\"subjectId\":1,\"publisher\":\"GHP.us\"},{\"id\":21382138,\"bookId\":21382138,\"userId\":1838771,\"createdAt\":\"2022-09-22T20:29:34+02:00\",\"kind\":\"Informacja\",\"title\":\"grupahakerskapiotr.us - nasza strona\",\"reformLevel\":null,\"subject\":\"Strona\",\"subjectId\":1,\"publisher\":\"GHP.us\"}]}")	
	} else if strings.Contains(resp.Request.URL.Path, "ksiazka") && resp.Request.Method == "GET" && !strings.HasSuffix(resp.Request.URL.Path, ".json") { //Sprawdzanie czy kliknelismy refresz (F5)
		//bierzemy nowe konto B)
		currentAccountIndex += 1
		currentAccountIndex = currentAccountIndex % len(accounts)
		fmt.Printf("Zmieniłem konto na: " + strconv.Itoa(currentAccountIndex) + "\n")
	}

	b = bytes.Replace(b, []byte("Rozwiąż z nami "), []byte("Nuh uh"), -1)
	//easter egg :troll:
	b = bytes.Replace(b, []byte("https://odrabiamy.pl/razem"), []byte("https://grupahakerskapiotr.us/krater"), -1)

	var newMail string = "ID: " + strconv.Itoa(currentAccountIndex) + " PWNED"
	b = bytes.Replace(b, []byte(accounts[currentAccountIndex].Mail), []byte(newMail), -1)
	b = bytes.Replace(b, []byte(accounts[currentAccountIndex].Session), []byte(newMail), -1)
	b = bytes.Replace(b, []byte("GTM-KKMZR7"), []byte("G-PLL1Q6BV6J"), -1)
	body := ioutil.NopCloser(bytes.NewReader(b))
	resp.Body = body
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	return nil
}

func main() {
	//Zczytanie userlist.json do []accounts
	currentAccountIndex = 0
	jsonAccountsFile, _ := os.Open("userlist.json")
	byteAccountsValue, _ := ioutil.ReadAll(jsonAccountsFile)
	json.Unmarshal(byteAccountsValue, &accounts)

	jsonConfigFile, _ := os.Open("config.json")
	byteConfigValue, _ := ioutil.ReadAll(jsonConfigFile)
	json.Unmarshal(byteConfigValue, &config)

	proxy := &httputil.ReverseProxy{
		Transport: roundTripper(rt),
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = "odrabiamy.pl"
		},
	}
	log.Fatal(http.ListenAndServe(config.BindAddress, proxy))
}

func rt(req *http.Request) (*http.Response, error) {
	req.Host = "odrabiamy.pl"
	req.Header.Set("User-Agent", "O skurwesyn")

        //cookie, err := req.Cookie("spokostoje")
        //redirect := http.Response{
        //       Body: ioutil.NopCloser(bytes.NewBufferString("ayyyy caramba...")),
        //       StatusCode: 302,
        //       Header: make(http.Header),
        //}
        //redirect.Header.Set("Location", "https://grupahakerskapiotr.us")

        //if err != nil {
        //       return &redirect, nil
        //}

        //if cookie.Value != "Jacek Jaworek" {
        //       return &redirect, nil
        //}
        
	if strings.HasPrefix(req.URL.Path, "/api/v1.3/uzytkownicy/usun") ||
		strings.HasPrefix(req.URL.Path, "/api/v1.3/registrations/update_password") ||
		strings.HasPrefix(req.URL.Path, "/api/v1.3/wiadomosci/wyslij") ||
		strings.HasPrefix(req.URL.Path, "/api/v3/print_screen_abuse") ||
		strings.HasPrefix(req.URL.Path, "/api/log") ||
		strings.HasPrefix(req.URL.Path, "/api/v3/comment") ||
		strings.HasPrefix(req.URL.Path, "/api/v3/rating") ||
		strings.HasPrefix(req.URL.Path, "/api/v3/author_thanks") ||
		strings.HasPrefix(req.URL.Path, "/api/v3/exercise_messages") ||
		strings.HasPrefix(req.URL.Path, "/api/v3/qa_post_messages") ||
		(strings.Contains(req.URL.Path, "/api/v3/qa_posts") && strings.Contains(req.URL.Path, "/like")) ||
		(strings.HasPrefix(req.URL.Path, "/api/v3/user_books") && req.Method == "POST" || req.Method == "DELETE") {
		t := http.Response{
			Body: ioutil.NopCloser(bytes.NewBufferString("nie psuj")),
			StatusCode: 400,
		}

		return &t, nil
	}
	cookie := &http.Cookie{Name: "__Secure-next-auth.session-token", Value: accounts[currentAccountIndex].Session, HttpOnly: false}
	/*if val, ok := req.Header["Authorization"]; ok {
		bearer := strings.Split(val[0], " ")[1]
		decoded, _ := base64.StdEncoding.DecodeString(bearer)
		req.Header.Set("Authorization", decrypt([]byte("jajcarz key 1234"), decoded))
		fmt.Printf("rt() Authorization \n")
	}*/
	delete(req.Header, "Accept-Encoding") // hack: zeby rewrite body dzialal (dekompresja nie dziala)
	//cookie := &http.Cookie{Name: "__Secure-next-auth.session-token", Value: accounts[currentAccountIndex].Session, HttpOnly: false}
	req.AddCookie(cookie)

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	err = rewriteBody(resp, config.Strona)
	return resp, err
}

// roundTripper makes func signature a http.RoundTripper
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
