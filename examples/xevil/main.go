package main

import (
	"context"
	"fmt"

	"github.com/jordansinko/gocaptcha"
)

func main() {
	ctx := context.TODO()
	cp := gocaptcha.NewXevil("apiKey")
	cs := gocaptcha.NewCaptchaSolver(cp)

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
