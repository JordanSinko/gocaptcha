package gocaptcha

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aidarkhanov/nanoid/v2"
	"gitlab.com/aycd-inc/autosolve-clients-v3/autosolve-client-go/autosolve"
)

type Aycd struct {
	clientId  string
	apiKey    string
	service   *service
	connected bool
	mu        sync.Mutex
}

type response struct {
	Cancelled bool
	Timeout   bool
	Response  autosolve.CaptchaResponse
}

func (r *response) SolveResponse() *autosolve.CaptchaTokenResponse {
	return r.Response.(*autosolve.CaptchaTokenResponse)
}

func (r *response) CancelResponse() *autosolve.CaptchaTokenCancelResponse {
	return r.Response.(*autosolve.CaptchaTokenCancelResponse)
}

type listener struct {
	autosolve.Listener
	service *service
}

func (l *listener) OnStatusChanged(status autosolve.Status) {
	//log.Printf("Status changed: %v\n", status)
}

func (l *listener) OnError(err error) {
	//log.Printf("Error: %v\n", err)
}

func (l *listener) OnTokenResponse(tokenResponse *autosolve.CaptchaTokenResponse) {
	solveResponse := &response{
		Cancelled: false,
		Response:  tokenResponse,
	}
	respChan := l.service.responses[tokenResponse.TaskId]
	if respChan != nil {
		respChan <- solveResponse
	}
}

func (l *listener) OnTokenCancelResponse(cancelResponse *autosolve.CaptchaTokenCancelResponse) {
	solveResponse := &response{
		Cancelled: true,
		Response:  cancelResponse,
	}
	for _, request := range cancelResponse.Requests {
		respChan := l.service.responses[request.TaskId]
		if respChan != nil {
			respChan <- solveResponse
		}
	}
}

type service struct {
	listener  *listener
	session   autosolve.Session
	responses map[string]chan *response
}

func NewAycd(clientId string, apiKey string) *Aycd {

	autosolve.Init(clientId)
	service := &service{responses: make(map[string]chan *response)}
	service.listener = &listener{service: service}

	return &Aycd{
		clientId: clientId,
		apiKey:   apiKey,
		service:  service,
		mu:       sync.Mutex{},
	}
}

func (a *Aycd) SolveImageCaptcha(ctx context.Context, settings *Settings, payload *ImageCaptchaPayload) (ICaptchaResponse, error) {

	if err := a.connect(); err != nil {
		return nil, err
	}

	return nil, errors.New("not implemented")
}

func (a *Aycd) SolveRecaptchaV2(ctx context.Context, settings *Settings, payload *RecaptchaV2Payload) (ICaptchaResponse, error) {

	if err := a.connect(); err != nil {
		return nil, err
	}

	taskId, _ := nanoid.New()

	request := &autosolve.CaptchaTokenRequest{
		TaskId:  taskId,
		Url:     payload.EndpointUrl,
		SiteKey: payload.EndpointKey,
		Version: autosolve.ReCaptchaV2Checkbox,
	}

	if payload.IsEnterprise {
		request.Version = autosolve.ReCaptchaV2Enterprise
	} else if payload.IsInvisibleCaptcha {
		request.Version = autosolve.ReCaptchaV2Invisible
	}

	response, err := a.solveTask(ctx, settings, request)

	if err != nil {
		return nil, err
	}

	return response, nil
}

func (a *Aycd) SolveRecaptchaV3(ctx context.Context, settings *Settings, payload *RecaptchaV3Payload) (ICaptchaResponse, error) {

	if err := a.connect(); err != nil {
		return nil, err
	}

	taskId, _ := nanoid.New()

	request := &autosolve.CaptchaTokenRequest{
		TaskId:   taskId,
		Url:      payload.EndpointUrl,
		SiteKey:  payload.EndpointKey,
		Version:  autosolve.ReCaptchaV3,
		Action:   payload.Action,
		MinScore: payload.MinScore,
	}

	response, err := a.solveTask(ctx, settings, request)

	if err != nil {
		return nil, err
	}

	return response, nil
}

func (a *Aycd) SolveHCaptcha(ctx context.Context, settings *Settings, payload *HCaptchaPayload) (ICaptchaResponse, error) {

	if err := a.connect(); err != nil {
		return nil, err
	}

	return nil, errors.New("not implemented")
}

func (a *Aycd) SolveTurnstile(ctx context.Context, settings *Settings, payload *TurnstilePayload) (ICaptchaResponse, error) {

	if err := a.connect(); err != nil {
		return nil, err
	}

	return nil, errors.New("not implemented")
}

func (a *Aycd) SolveWaf(ctx context.Context, settings *Settings, payload *WafPayload) (ICaptchaResponse, error) {
	return nil, errors.New("not supported")
}

func (a *Aycd) connect() error {

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.connected && a.service.session != nil {
		return nil
	}

	session, err := autosolve.GetSession(a.apiKey)
	if err != nil {
		return err
	}

	session.SetListener(a.service.listener)

	if err := session.Open(); err != nil {
		return err
	}

	a.service.session = session
	a.connected = true

	return nil
}

func (a *Aycd) solveTask(ctx context.Context, settings *Settings, request *autosolve.CaptchaTokenRequest) (*CaptchaResponse, error) {

	if a.service.session == nil {
		return nil, autosolve.InvalidSessionError
	}

	channel := make(chan *response)
	a.service.responses[request.TaskId] = channel
	a.service.session.Send(request)

	res := <-channel

	if res.Cancelled {
		return nil, fmt.Errorf("the request was cancelled")
	} else if res.Timeout {
		return nil, fmt.Errorf("the request timed out")
	}

	t := res.SolveResponse().Token

	return &CaptchaResponse{solution: t, taskId: request.TaskId}, nil

}

var _ IProvider = (*Aycd)(nil)
