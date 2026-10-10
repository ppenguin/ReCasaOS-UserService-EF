package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/config"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/gatewayclient"
	"github.com/IceWhaleTech/CasaOS-Common/external"
)

// bus client presents the gateway service credential
func TestMessageBusClientSendsServiceCredential(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	authorization := make(chan string, 1)
	bus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer bus.Close()

	runtimePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(runtimePath, external.MessageBusAddressFilename), []byte(bus.URL), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimePath, gatewayclient.ServiceTokenFilename), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := config.CommonInfo.RuntimePath
	config.CommonInfo.RuntimePath = runtimePath
	t.Cleanup(func() { config.CommonInfo.RuntimePath = previous })

	if _, err := (&store{}).MessageBus().GetEventTypesWithResponse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := <-authorization; got != "Bearer "+token {
		t.Fatalf("Authorization = %q, want the service credential", got)
	}
}
