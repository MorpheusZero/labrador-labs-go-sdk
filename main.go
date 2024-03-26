package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

type AccessTokenResponse struct {
	TokenType        string    `json:"tokenType"`
	AccessToken      string    `json:"accessToken"`
	ExpiresIn        int       `json:"expiresIn"`
	RefreshExpiresIn int       `json:"refreshExpiresIn"`
	Scopes           []string  `json:"scopes"`
	RefreshToken     string    `json:"refreshToken"`
	IssuedAt         time.Time `json:"issuedAt"`
}

type LabLabsClient struct {
	APIBaseURL     string
	OrganizationID string
	Token          string
}

type AnalyzeResultsResponse struct {
	Content []struct {
		Name           string    `json:"name"`
		ProjectType    string    `json:"projectType"`
		ID             string    `json:"id"`
		RegisteredAt   time.Time `json:"registeredAt"`
		AnalysisID     string    `json:"analysisId"`
		AnalysisStatus string    `json:"analysisStatus"`
		Result         struct {
			Total                int `json:"total"`
			CodeSnippet          int `json:"codeSnippet"`
			Library              int `json:"library"`
			CodeSnippetAndSource int `json:"codeSnippetAndSource"`
			Ospkg                int `json:"ospkg"`
			Binary               int `json:"binary"`
			Sw                   int `json:"sw"`
			Vulnerabilities      struct {
				Total          int `json:"total"`
				CvssV2high     int `json:"cvssV2high"`
				CvssV2medium   int `json:"cvssV2medium"`
				CvssV2low      int `json:"cvssV2low"`
				CvssV2unknown  int `json:"cvssV2unknown"`
				CvssV3critical int `json:"cvssV3critical"`
				CvssV3high     int `json:"cvssV3high"`
				CvssV3medium   int `json:"cvssV3medium"`
				CvssV3low      int `json:"cvssV3low"`
				CvssV3none     int `json:"cvssV3none"`
				CvssV3unknown  int `json:"cvssV3unknown"`
				LppHigh        int `json:"lppHigh"`
				LppMedium      int `json:"lppMedium"`
				LppLow         int `json:"lppLow"`
				LppUndefined   int `json:"lppUndefined"`
			} `json:"vulnerabilities"`
			Licenses struct {
				Total              int `json:"total"`
				Protective         int `json:"protective"`
				Permissive         int `json:"permissive"`
				Deprecated         int `json:"deprecated"`
				Unknown            int `json:"unknown"`
				Blocked            int `json:"blocked"`
				TotalLicense       int `json:"totalLicense"`
				ProtectiveLicense  int `json:"protectiveLicense"`
				PermissiveLicense  int `json:"permissiveLicense"`
				DeprecatedLicense  int `json:"deprecatedLicense"`
				UnknownLicense     int `json:"unknownLicense"`
				BlockedLicense     int `json:"blockedLicense"`
				CompatLicenseCount struct {
					Conflict     int `json:"conflict"`
					Incompatible int `json:"incompatible"`
					Unknown      int `json:"unknown"`
				} `json:"compatLicenseCount"`
			} `json:"licenses"`
			Policy struct {
				Allowed                 int `json:"allowed"`
				Blocked                 int `json:"blocked"`
				UserDefinedComponents   int `json:"userDefinedComponents"`
				UserDefinedCodeSnippets int `json:"userDefinedCodeSnippets"`
			} `json:"policy"`
			Excluded struct {
				ExcludedFiles      int `json:"excludedFiles"`
				ExcludedFilesBytes int `json:"excludedFilesBytes"`
			} `json:"excluded"`
		} `json:"result"`
		RecentAnalyzedAt        time.Time `json:"recentAnalyzedAt"`
		SourceID                string    `json:"sourceId"`
		SourceType              string    `json:"sourceType"`
		VulnCodeSnippetsTotal   int       `json:"vulnCodeSnippetsTotal"`
		VulnFilesTotal          int       `json:"vulnFilesTotal"`
		VulnComponentsTotal     int       `json:"vulnComponentsTotal"`
		LicensesTotal           int       `json:"licensesTotal"`
		UserDefinedComponents   int       `json:"userDefinedComponents"`
		UserDefinedCodeSnippets int       `json:"userDefinedCodeSnippets"`
		Allowed                 int       `json:"allowed"`
		Blocked                 int       `json:"blocked"`
		AnalysisCnt             int       `json:"analysisCnt"`
	} `json:"content"`
}

func CreateLabLabsClient(organizationId string) (client *LabLabsClient) {
	return &LabLabsClient{
		APIBaseURL:     "https://labrador.labradorlabs.ai/api/v2",
		OrganizationID: organizationId,
	}
}

func (client *LabLabsClient) Authenticate(username string, password string) (err error) {
	url := client.APIBaseURL + "/tokens/organizations/" + client.OrganizationID

	body := []byte(fmt.Sprintf(`{
		"account": {
			"id": "%v",
			"password": "%v"
		}
	}`, username, password))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("[LabLabsSDK] - NewRequest - An error occurred when attempting to authenticate with Lab Labs. ", err)
		return nil
	}

	req.Header.Add("Content-Type", "application/json")

	httpClient := &http.Client{}
	res, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("[LabLabsSDK] - PerformRequest - An error occurred when attempting to authenticate with Lab Labs. ", err)
		return nil
	}

	defer res.Body.Close()

	//itm, err := ioutil.ReadAll(res.Body)
	//bodyString := string(itm)
	//fmt.Println(bodyString)

	var tokenResponse AccessTokenResponse
	err = json.NewDecoder(res.Body).Decode(&tokenResponse)
	if err != nil {
		fmt.Println("[LabLabsSDK] - DecodeResponse - Error decoding token response:", err)
		return err
	}

	client.Token = tokenResponse.AccessToken

	fmt.Println("[LabLabsSDK] - Successfully Authenticated!")

	return nil
}

func (client *LabLabsClient) GetMostRecentAnalyzeResultsForAllProjects() (results *AnalyzeResultsResponse, err error) {
	url := client.APIBaseURL + "/groups/" + os.Getenv("GROUP_ID") + "/projects?all=false&page=0&size=50&sort=recentAnalyzedAt,DESC&status=DONE"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("[LabLabsSDK] - NewRequest - An error occurred when attempting to get results from Lab Labs. ", err)
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("authToken", client.Token)

	httpClient := &http.Client{}
	res, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("[LabLabsSDK] - PerformRequest - An error occurred when attempting to get results from Lab Labs. ", err)
		return nil, err
	}

	defer res.Body.Close()

	var resultsResponse AnalyzeResultsResponse
	err = json.NewDecoder(res.Body).Decode(&resultsResponse)
	if err != nil {
		fmt.Println("[LabLabsSDK] - DecodeResponse - Error decoding results response:", err)
		return nil, err
	}

	fmt.Println("[LabLabsSDK] - Received [" + fmt.Sprintf(strconv.Itoa(len(resultsResponse.Content))) + "] results...")

	for _, c := range resultsResponse.Content {
		fmt.Printf("Name: %s\n", c.Name)
	}

	return &resultsResponse, nil
}
