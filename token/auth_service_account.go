package token

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/fabric8-services/fabric8-tenant/configuration"
	"github.com/pkg/errors"
)

type ClusterTokenService interface {
	Get() error
}

type ClusterTokenClient struct {
	Config                  *configuration.Data
	AuthServiceAccountToken string
}

func (c *ClusterTokenClient) Get() error {
	payload := strings.NewReader("grant_type=" + c.Config.GetAuthGrantType() + "&client_id=" +
		c.Config.GetAuthClientID() + "&client_secret=" + c.Config.GetClientSecret())

	req, err := http.NewRequest("POST", c.Config.GetAuthURL()+"/api/token", payload)
	if err != nil {
		return errors.Wrapf(err, "error creating request object")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "error while doing the request")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrapf(err, "error reading response")
	}

	if err := validateError(res.StatusCode, body); err != nil {
		return errors.Wrapf(err, "error from server %q", c.Config.GetAuthURL())
	}

	// parse the token from the output
	if c.AuthServiceAccountToken, err = parseToken(body); err != nil {
		return err
	}

	return nil
}

func validateError(status int, body []byte) error {
	type authEerror struct {
		Code   string `json:"code,omitempty"`
		Detail string `json:"detail,omitempty"`
		Status string `json:"status,omitempty"`
		Title  string `json:"title,omitempty"`
	}

	type errorResponse struct {
		Errors []authEerror `json:"errors,omitempty"`
	}

	if status != http.StatusOK {
		var e errorResponse
		err := json.Unmarshal(body, &e)
		if err != nil {
			return errors.Wrapf(err, "could not unmarshal the response")
		}

		var output string
		for _, error := range e.Errors {
			output += fmt.Sprintf("%s: %s %s, %s\n", error.Title, error.Status, error.Code, error.Detail)
		}
		return fmt.Errorf("%s", output)
	}
	return nil
}
