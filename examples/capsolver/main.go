package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jordansinko/gocaptcha"
)

func main() {
	ctx := context.TODO()
	cp := gocaptcha.NewCapSolver("apiKey")
	cs := gocaptcha.NewCaptchaSolver(cp)

	// optional changes
	cs.SetPollInterval(time.Second * 1)
	cs.SetClient(&http.Client{})
	cs.SetInitialWaitTime(time.Second * 1)
	cs.SetMaxRetries(10)

	sol, err := cs.SolveRecaptchaV2(ctx, &gocaptcha.RecaptchaV2Payload{
		EndpointUrl:        "https://www.mlb.com",
		EndpointKey:        "6Lc5RpscAAAAALIbKaXoAqMzA2Mo2DTtzlrfqtJ6",
		IsInvisibleCaptcha: false,
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(sol.Solution())

}
