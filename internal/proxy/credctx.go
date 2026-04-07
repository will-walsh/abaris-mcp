package proxy

import "context"

type credContextKey struct{}

// WithServiceCredential stores a service credential in the context so that
// BackendTransport implementations can retrieve it without the Broker needing
// to know the transport's internal credential format.
func WithServiceCredential(ctx context.Context, cred string) context.Context {
	return context.WithValue(ctx, credContextKey{}, cred)
}

// ServiceCredentialFromContext retrieves the service credential stored by
// WithServiceCredential. Returns ("", false) if not set.
func ServiceCredentialFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(credContextKey{}).(string)
	return v, ok
}
