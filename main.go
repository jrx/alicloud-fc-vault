package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

func main() {
	fmt.Println("start listen port 9000")

	fmt.Println("ACCESS_KEY:", os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"))
	fmt.Println("SECRET_KEY:", os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"))
	fmt.Println("SECURITY_TOKEN:", os.Getenv("ALIBABA_CLOUD_SECURITY_TOKEN"))
	fmt.Println("REGION:", os.Getenv("FC_REGION"))
	fmt.Println("ROLE:", os.Getenv("ROLE_NAME"))

	http.HandleFunc("/", HelloServer)
	http.ListenAndServe(":9000", nil)
}

// Generates the necessary data to send to the Vault server for generating a token.
// This is useful for other API clients to use.
// If "" is passed in for accessKeyID, accessKeySecret, and securityToken,
// attempts to use credentials set as env vars or available through instance metadata.
func GenerateLoginData(role string, creds auth.Credential, region string) (map[string]interface{}, error) {
	config := sdk.NewConfig()

	// This call always must be https but the config doesn't default to that.
	config.Scheme = "https"

	// Prepare to record the request using a proxy that will capture it and throw an error so it's not executed.
	capturer := &RequestCapturer{}
	transport := &http.Transport{}
	transport.Proxy = capturer.Proxy
	config.HttpTransport = transport

	client, err := sts.NewClientWithOptions(region, config, creds)
	if err != nil {
		return nil, err
	}

	// This method returns a response and an error. We're ignoring both because the response
	// will always be nil here, and the error will always be the error thrown by the Proxy
	// method below. We don't care about either of them, we just care about firing the request
	// so we can capture it on the way out and retrieve it for further use.
	client.GetCallerIdentity(sts.CreateGetCallerIdentityRequest())

	getCallerIdentityRequest, err := capturer.GetCapturedRequest()
	if err != nil {
		return nil, err
	}

	u := base64.StdEncoding.EncodeToString([]byte(getCallerIdentityRequest.URL.String()))
	b, err := json.Marshal(getCallerIdentityRequest.Header)
	if err != nil {
		return nil, err
	}
	headers := base64.StdEncoding.EncodeToString(b)
	return map[string]interface{}{
		"role":                     role,
		"identity_request_url":     u,
		"identity_request_headers": headers,
	}, nil
}

/*
RequestCapturer fulfills the Proxy method of http.Transport, so can be used to replace
the Proxy method on any transport method to simply capture the request.
Its Proxy method always returns an error so the request won't actually be fired.
This is useful for quickly finding out what final request a client is sending.
*/
type RequestCapturer struct {
	request *http.Request
}

func (r *RequestCapturer) Proxy(req *http.Request) (*url.URL, error) {
	r.request = req
	return nil, errors.New("throwing an error so we won't actually execute the request")
}

func (r *RequestCapturer) GetCapturedRequest() (*http.Request, error) {
	if r.request == nil {
		return nil, errors.New("no request captured")
	}
	return r.request, nil
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
	// requestId := r.Header.Get("x-fc-request-id")
	// fcLogger := gr.GetLogger().WithField("requestId", requestId)
	// fcLogger.Infof("This is a log from golang!")
	// fmt.Fprintf(w, "Hello, World!")
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	roleName := os.Getenv("ROLE_NAME")
	region := os.Getenv("FC_REGION")
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultNamespace := os.Getenv("VAULT_NAMESPACE")

	if vaultNamespace != "" {
		vaultNamespace += "/"
	}

	var creds auth.Credential

	loginData, err := GenerateLoginData(roleName, creds, region)
	if err != nil {
		panic(err)
	}

	// fmt.Printf("%q", loginData)

	b, err := json.Marshal(loginData)
	if err != nil {
		panic(err)
	}

	loginReq, err := http.NewRequest(http.MethodPost, vaultAddr+"/v1/"+vaultNamespace+"auth/alicloud/login", bytes.NewReader(b))
	if err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(loginReq)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Printf("response status code: %d\n", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", body)

	// Manually write the HTTP response
	buf.WriteString("HTTP/1.1 200 OK\r\n")
	buf.WriteString("Content-Type: text/plain\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(string(body))
	buf.Flush()
}
