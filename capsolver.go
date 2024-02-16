package gocaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jordansinko/gocaptcha/internal"
	j "github.com/ricardolonga/jsongo"
)

type CapSolver struct {
	apiKey string
}

type request struct {
	clientKey string
	task      map[string]interface{}
}

func NewCapSolver(apiKey string) *CapSolver {
	return &CapSolver{
		apiKey: apiKey,
	}
}

func (cp *CapSolver) SolveImageCaptcha(ctx context.Context, settings *Settings, payload *ImageCaptchaPayload) (ICaptchaResponse, error) {

	return nil, errors.New("not implemented")

}

func (cp *CapSolver) SolveRecaptchaV2(ctx context.Context, settings *Settings, payload *RecaptchaV2Payload) (ICaptchaResponse, error) {

	request := j.Object()

	request.Put("clientKey", cp.apiKey)

	task := j.Object()

	if payload.IsEnterprise {
		task.Put("type", "ReCaptchaV2EnterpriseTaskProxyLess")
	} else {
		task.Put("type", "ReCaptchaV2TaskProxyLess")
	}

	task.Put("websiteURL", payload.EndpointUrl)
	task.Put("websiteKey", payload.EndpointKey)

	if payload.IsInvisibleCaptcha {
		task.Put("isInvisible", payload.IsInvisibleCaptcha)
	}

	request.Put("task", task)

	// task.clientKey = cp.apiKey
	// task.task = make(map[string]interface{})

	// task.task["type"] = "ReCaptchaV2Task"
	// task.task["websiteURL"] = payload.EndpointUrl
	// task.task["websiteKey"] = payload.EndpointKey
	// task.task["isInvisible"] = payload.IsInvisibleCaptcha

	result, err := cp.solveTask(ctx, settings, request)

	if err != nil {
		return nil, err
	}

	// result.reportGood = cp.report("reportgood", result.taskId, settings)
	// result.reportBad = cp.report("reportbad", result.taskId, settings)
	return result, nil
}

func (cp *CapSolver) SolveRecaptchaV3(ctx context.Context, settings *Settings, payload *RecaptchaV3Payload) (ICaptchaResponse, error) {

	request := j.Object()

	request.Put("clientKey", cp.apiKey)

	task := j.Object()

	if payload.IsEnterprise {
		task.Put("type", "ReCaptchaV3EnterpriseTaskProxyLess")
	} else {
		task.Put("type", "ReCaptchaV3M1TaskProxyLess")
	}

	task.Put("websiteURL", payload.EndpointUrl)
	task.Put("websiteKey", payload.EndpointKey)
	task.Put("pageAction", payload.Action)

	if payload.ProxyUrl != "" {
		task.Put("type", "ReCaptchaV3Task")
		task.Put("proxy", payload.ProxyUrl)
	}

	request.Put("task", task)

	result, err := cp.solveTask(ctx, settings, request)

	if err != nil {
		return nil, err
	}

	// result.reportGood = cp.report("reportgood", result.taskId, settings)
	// result.reportBad = cp.report("reportbad", result.taskId, settings)
	return result, nil

}

func (cp *CapSolver) SolveHCaptcha(ctx context.Context, settings *Settings, payload *HCaptchaPayload) (ICaptchaResponse, error) {

	return nil, errors.New("not implemented")

}

func (cp *CapSolver) SolveTurnstile(ctx context.Context, settings *Settings, payload *TurnstilePayload) (ICaptchaResponse, error) {

	return nil, errors.New("not implemented")

}

func (cp *CapSolver) SolveWaf(ctx context.Context, settings *Settings, payload *WafPayload) (ICaptchaResponse, error) {
	request := j.Object()

	request.Put("clientKey", cp.apiKey)

	task := j.Object()

	task.Put("type", "AntiAwsWafTaskProxyLess")
	task.Put("websiteURL", payload.EndpointUrl)

	if payload.ProxyUrl != "" {
		task.Put("type", "AntiAwsWafTask")
		task.Put("proxy", payload.ProxyUrl)
	}

	request.Put("task", task)

	result, err := cp.solveTask(ctx, settings, request)

	if err != nil {
		return nil, err
	}

	// result.reportGood = cp.report("reportgood", result.taskId, settings)
	// result.reportBad = cp.report("reportbad", result.taskId, settings)
	return result, nil
}

func (cp *CapSolver) report(action, taskId string, settings *Settings) func(ctx context.Context) error {
	type response struct {
		Status    int    `json:"status"`
		Request   string `json:"request"`
		ErrorText string `json:"error_text"`
	}

	return func(ctx context.Context) error {
		var body url.Values
		body.Set("key", cp.apiKey)
		body.Set("action", action)
		body.Set("id", taskId)
		body.Set("json", "1")

		reqUrl := fmt.Sprintf(``)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqUrl, strings.NewReader(body.Encode()))

		if err != nil {
			return err
		}

		resp, err := settings.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var jsonResp response
		if err := json.Unmarshal(respBody, &jsonResp); err != nil {
			return err
		}

		if jsonResp.Status == 0 {
			return fmt.Errorf("%v: %v", jsonResp.Request, jsonResp.ErrorText)
		}

		return nil
	}
}

func (cp *CapSolver) solveTask(ctx context.Context, settings *Settings, task j.O) (*CaptchaResponse, error) {
	taskId, err := cp.createTask(ctx, settings, task)

	if err != nil {
		return nil, err
	}

	if err := internal.SleepWithContext(ctx, settings.initialWaitTime); err != nil {
		return nil, err
	}

	for i := 0; i < settings.maxRetries; i++ {
		answer, err := cp.getResult(ctx, settings, taskId)

		if err != nil {
			return nil, err
		}

		if answer != "" {
			return &CaptchaResponse{solution: answer, taskId: taskId}, nil
		}

		if err := internal.SleepWithContext(ctx, settings.pollInterval); err != nil {
			return nil, err
		}
	}

	return nil, errors.New("max tries exceeded")
}

func (cp *CapSolver) createTask(ctx context.Context, settings *Settings, payload j.O) (string, error) {
	type response struct {
		ErrorId          int    `json:"errorId"`
		ErrorCode        string `json:"errorCode"`
		ErrorDescription string `json:"errorDescription"`
		TaskId           string `json:"taskId"`
	}

	reqBody := payload.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, `https://api.capsolver.com/createTask`, strings.NewReader(reqBody))

	if err != nil {
		return "", nil
	}

	resp, err := settings.client.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	var jsonResp response

	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return "", err
	}

	if jsonResp.TaskId == "" {
		return "", fmt.Errorf("%v: %v", jsonResp.ErrorCode, jsonResp.ErrorDescription)
	}

	return jsonResp.TaskId, nil
}

func (cp *CapSolver) getResult(ctx context.Context, settings *Settings, taskId string) (string, error) {
	type response struct {
		ErrorId          int    `json:"errorId"`
		ErrorCode        string `json:"errorCode"`
		ErrorDescription string `json:"errorDescription"`
		TaskId           string `json:"taskId"`
		Status           string `json:"status"`
		Solution         struct {
			Text               string `json:"text"`
			GRecaptchaResponse string `json:"gRecaptchaResponse"`
		} `json:"solution"`
	}

	resBody, _ := json.Marshal(map[string]string{
		"clientId": cp.apiKey,
		"taskId":   taskId,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, `https://api.capsolver.com/getTaskResult`, bytes.NewBuffer(resBody))

	if err != nil {
		return "", err
	}

	resp, err := settings.client.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	var jsonResp response
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return "", err
	}

	if jsonResp.ErrorId != 0 {
		return "", fmt.Errorf("%v: %v", jsonResp.ErrorCode, jsonResp.ErrorDescription)
	}

	if jsonResp.ErrorId == 0 && jsonResp.Status != "ready" {
		return "", nil
	}

	return jsonResp.Solution.GRecaptchaResponse, nil
}

var _ IProvider = (*CapSolver)(nil)
