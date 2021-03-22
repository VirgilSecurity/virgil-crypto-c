package sdk_core

import "C"

/*
* HTTP client interface.
 */
type HttpClient interface {
	context

	/*
	 * Send given request over HTTP.
	 */
	Send(httpRequest *HttpRequest) (*HttpResponse, error)

	/*
	 * Release underlying C context.
	 */
	Delete()
}
