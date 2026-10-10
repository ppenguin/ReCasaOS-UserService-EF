//go:generate bash scripts/generate-api.sh
package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/codegen/message_bus"
	"github.com/EdmundFu-233/ReCasaOS-UserService/common"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/config"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/processlock"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/signingkey"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/sqlite"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userbootstrap"
	"github.com/EdmundFu-233/ReCasaOS-UserService/route"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
	"github.com/IceWhaleTech/CasaOS-Common/external"
	"github.com/IceWhaleTech/CasaOS-Common/model"
	util_http "github.com/IceWhaleTech/CasaOS-Common/utils/http"
	"github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/coreos/go-systemd/daemon"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const localhost = "127.0.0.1"

const (
	defaultBootstrapSealPath = "/etc/casaos/recasaos-user-bootstrap.seal"
	defaultProcessLockPath   = "/run/lock/recasaos-user-service.lock"
)

var (
	commit = "private build"
	date   = "private build"

	//go:embed api/index.html
	_docHTML string

	//go:embed api/user-service/openapi.yaml
	_docYAML string

	//go:embed build/sysroot/etc/casaos/user-service.conf.sample
	_confSample string
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, os.Geteuid(), os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer, effectiveUID int, getenv func(string) string) error {
	if len(args) > 0 && args[0] == "bootstrap-admin" {
		return runBootstrapAdmin(args[1:], stdout, stderr, effectiveUID, getenv)
	}
	if len(args) > 0 && args[0] == "reset-admin-password" {
		return runResetAdminPassword(args[1:], stdout, stderr, effectiveUID, getenv)
	}
	if len(args) > 0 && args[0] == "reset-user-password" {
		return runResetUserPassword(args[1:], stdout, stderr, effectiveUID, getenv)
	}
	return runServer(args, stdout, stderr, effectiveUID)
}

func runServer(args []string, stdout, stderr io.Writer, effectiveUID int) error {
	flags := flag.NewFlagSet("casaos-user-service", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configFlag := flags.String("c", "", "config address")
	dbFlag := flags.String("db", "", "database directory")
	sealFlag := flags.String("bootstrap-seal", defaultBootstrapSealPath, "bootstrap seal outside the database directory")
	lockFlag := flags.String("process-lock", defaultProcessLockPath, "daemon/bootstrap/reset exclusion lock")
	resetUserFlag := flags.Bool("ru", false, "disabled legacy password reset")
	_ = flags.String("user", "", "disabled legacy reset username")
	versionFlag := flags.Bool("v", false, "version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *versionFlag {
		fmt.Fprintf(stdout, "v%s\n", common.Version)
		return nil
	}
	if *resetUserFlag {
		return errors.New("-ru is disabled because it exposed plaintext passwords; use an authenticated local recovery workflow")
	}
	processLock, err := processlock.Acquire(*lockFlag, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer processLock.Close()

	fmt.Fprintln(stdout, "git commit:", commit)
	fmt.Fprintln(stdout, "build date:", date)
	config.InitSetup(*configFlag, _confSample)
	logger.LogInit(config.AppInfo.LogPath, config.AppInfo.LogSaveName, config.AppInfo.LogFileExt)
	if *dbFlag == "" {
		*dbFlag = config.AppInfo.DBPath
	}

	if err := requireSealOutsideDatabase(*dbFlag, *sealFlag); err != nil {
		return err
	}
	sqliteDB, err := sqlite.GetDb(*dbFlag)
	if err != nil {
		return err
	}
	seal := userbootstrap.NewFileSeal(*sealFlag, uint32(effectiveUID))
	sqlDB, err := sqliteDB.DB()
	if err != nil {
		return fmt.Errorf("access user database pool: %w", err)
	}
	initializationState, err := userbootstrap.ReconcileState(context.Background(), sqlDB, seal)
	if err != nil {
		return err
	}
	signingKey, created, err := signingkey.LoadOrCreate(filepath.Join(*dbFlag, signingkey.Filename), uint32(effectiveUID))
	switch {
	case err != nil:
		// sessions do not survive a restart, as before; nothing is weakened
		logger.Error("signing key not persisted, using a key held in memory", zap.Error(err))
		signingKey = nil
	case created:
		logger.Info("new signing key: existing sessions are signed out once")
	}
	service.MyService = service.NewService(sqliteDB, config.CommonInfo.RuntimePath, initializationState, signingKey)
	if service.MyService == nil || service.MyService.User() == nil {
		return errors.New("initialize user service")
	}

	v1Router := route.InitRouter()
	v2Router := route.InitV2Router()
	v2DocRouter := route.InitV2DocRouter(_docHTML, _docYAML)

	_, publicKey := service.MyService.User().GetKeyPair()

	jswkJSON, err := authsecurity.GeneratePublicJWKS(publicKey)
	if err != nil {
		return fmt.Errorf("generate JWKS document: %w", err)
	}

	mux := &util_http.HandlerMultiplexer{
		HandlerMap: map[string]http.Handler{
			"v1":                                    v1Router,
			"v2":                                    v2Router,
			"doc":                                   v2DocRouter,
			strings.SplitN(jwt.JWKSPath, "/", 2)[0]: jwt.JWKSHandler(jswkJSON),
		},
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(localhost, "0"))
	if err != nil {
		return fmt.Errorf("listen for user service: %w", err)
	}
	defer listener.Close()

	apiPaths := []string{
		"/v1/users",
		route.V2APIPath,
		route.V2DocPath,
		"/" + jwt.JWKSPath,
	}
	for _, v := range apiPaths {
		err = service.MyService.Gateway().CreateRoute(&model.Route{
			Path:   v,
			Target: "http://" + listener.Addr().String(),
		})

		if err != nil {
			return fmt.Errorf("register gateway route %s: %w", v, err)
		}
	}

	// write address file
	addressFilePath, err := writeAddressFile(config.CommonInfo.RuntimePath, external.UserServiceAddressFilename, "http://"+listener.Addr().String())
	if err != nil {
		return fmt.Errorf("write user service address: %w", err)
	}

	if supported, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		logger.Error("Failed to notify systemd that user service is ready", zap.Any("error", err))
	} else if supported {
		logger.Info("Notified systemd that user service is ready")
	} else {
		logger.Info("This process is not running as a systemd service.")
	}
	go route.EventListen()
	logger.Info("User service is listening...", zap.Any("address", listener.Addr().String()), zap.String("filepath", addressFilePath))

	var events []message_bus.EventType
	events = append(events, message_bus.EventType{Name: "zimaos:user:save_config", SourceID: common.SERVICENAME, PropertyTypeList: []message_bus.PropertyType{}})
	// register at message bus
	for i := 0; i < 10; i++ {
		response, err := service.MyService.MessageBus().RegisterEventTypesWithResponse(context.Background(), events)
		if err != nil {
			logger.Error("error when trying to register one or more event types - some event type will not be discoverable", zap.Error(err))
		}
		if response != nil && response.StatusCode() != http.StatusOK {
			logger.Error("error when trying to register one or more event types - some event type will not be discoverable", zap.String("status", response.Status()), zap.String("body", string(response.Body)))
		}
		if response != nil && response.StatusCode() == http.StatusOK {
			break
		}
		time.Sleep(time.Second)
	}

	s := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // fix G112: Potential slowloris attack (see https://github.com/securego/gosec)
	}

	err = s.Serve(listener) // not using http.serve() to fix G114: Use of net/http serve function that has no support for setting timeouts (see https://github.com/securego/gosec)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve user service: %w", err)
	}
	return nil
}

const (
	credentialsDirectoryEnvironment = "CREDENTIALS_DIRECTORY"
	usernameCredentialName          = "recasaos.admin.username"
	passwordCredentialName          = "recasaos.admin.password"
	newPasswordCredentialName       = "recasaos.admin.new-password"
	maximumCredentialBytes          = 1024
)

func runBootstrapAdmin(args []string, stdout, stderr io.Writer, effectiveUID int, getenv func(string) string) error {
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configFlag := flags.String("c", "", "config address")
	dbFlag := flags.String("db", "", "database directory")
	userDataFlag := flags.String("user-data", "", "user data directory")
	sealFlag := flags.String("bootstrap-seal", defaultBootstrapSealPath, "bootstrap seal outside the database directory")
	lockFlag := flags.String("process-lock", defaultProcessLockPath, "daemon/bootstrap/reset exclusion lock")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("bootstrap-admin accepts no username or password arguments")
	}
	if effectiveUID != 0 {
		return errors.New("bootstrap-admin requires effective uid 0")
	}
	processLock, err := processlock.Acquire(*lockFlag, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer processLock.Close()

	credentialsDirectory := getenv(credentialsDirectoryEnvironment)
	if credentialsDirectory == "" {
		return fmt.Errorf("%s is not set; use systemd LoadCredential with %s and %s", credentialsDirectoryEnvironment, usernameCredentialName, passwordCredentialName)
	}
	usernameBytes, err := readCredential(credentialsDirectory, usernameCredentialName, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer erase(usernameBytes)
	passwordBytes, err := readCredential(credentialsDirectory, passwordCredentialName, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer erase(passwordBytes)

	if *dbFlag == "" || *userDataFlag == "" {
		config.InitSetup(*configFlag, _confSample)
		if *dbFlag == "" {
			*dbFlag = config.AppInfo.DBPath
		}
		if *userDataFlag == "" {
			*userDataFlag = config.AppInfo.UserDataPath
		}
	}
	if err := requireSealOutsideDatabase(*dbFlag, *sealFlag); err != nil {
		return err
	}
	db, err := sqlite.GetBootstrapDb(*dbFlag)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("access user database pool: %w", err)
	}
	defer sqlDB.Close()

	seal := userbootstrap.NewFileSeal(*sealFlag, uint32(effectiveUID))
	_, err = service.BootstrapAdmin(context.Background(), db, seal, string(usernameBytes), passwordBytes, func(userID int64) error {
		return secureUserDataDirectory(filepath.Join(*userDataFlag, strconv.FormatInt(userID, 10)))
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "administrator bootstrap completed")
	return nil
}

func runResetAdminPassword(args []string, stdout, stderr io.Writer, effectiveUID int, getenv func(string) string) error {
	flags := flag.NewFlagSet("reset-admin-password", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configFlag := flags.String("c", "", "config address")
	dbFlag := flags.String("db", "", "database directory")
	sealFlag := flags.String("bootstrap-seal", defaultBootstrapSealPath, "bootstrap seal outside the database directory")
	lockFlag := flags.String("process-lock", defaultProcessLockPath, "daemon/bootstrap/reset exclusion lock")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("reset-admin-password accepts no username or password arguments")
	}
	if effectiveUID != 0 {
		return errors.New("reset-admin-password requires effective uid 0")
	}
	processLock, err := processlock.Acquire(*lockFlag, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer processLock.Close()

	credentialsDirectory := getenv(credentialsDirectoryEnvironment)
	if credentialsDirectory == "" {
		return fmt.Errorf("%s is not set; use systemd LoadCredential with %s and %s", credentialsDirectoryEnvironment, usernameCredentialName, newPasswordCredentialName)
	}
	usernameBytes, err := readCredential(credentialsDirectory, usernameCredentialName, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer erase(usernameBytes)
	passwordBytes, err := readCredential(credentialsDirectory, newPasswordCredentialName, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer erase(passwordBytes)

	if *dbFlag == "" {
		config.InitSetup(*configFlag, _confSample)
		*dbFlag = config.AppInfo.DBPath
	}
	if err := requireSealOutsideDatabase(*dbFlag, *sealFlag); err != nil {
		return err
	}
	db, err := sqlite.GetExistingDb(*dbFlag)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("access user database pool: %w", err)
	}
	defer sqlDB.Close()

	seal := userbootstrap.NewFileSeal(*sealFlag, uint32(effectiveUID))
	if err := service.ResetAdminPassword(context.Background(), db, seal, string(usernameBytes), passwordBytes); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "administrator password reset completed")
	return nil
}

const (
	userUsernameCredentialName    = "recasaos.user.username"
	userNewPasswordCredentialName = "recasaos.user.new-password"
)

// runResetUserPassword implements the local-only recovery workflow for one
// exact existing non-administrator account. Like the administrator reset it
// accepts no credentials through argv, environment values, HTTP, or logs:
// the username and replacement password arrive only as systemd credentials,
// and administrator targets are refused without promotion.
func runResetUserPassword(args []string, stdout, stderr io.Writer, effectiveUID int, getenv func(string) string) error {
	flags := flag.NewFlagSet("reset-user-password", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configFlag := flags.String("c", "", "config address")
	dbFlag := flags.String("db", "", "database directory")
	sealFlag := flags.String("bootstrap-seal", defaultBootstrapSealPath, "bootstrap seal outside the database directory")
	lockFlag := flags.String("process-lock", defaultProcessLockPath, "daemon/bootstrap/reset exclusion lock")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("reset-user-password accepts no username or password arguments")
	}
	if effectiveUID != 0 {
		return errors.New("reset-user-password requires effective uid 0")
	}
	processLock, err := processlock.Acquire(*lockFlag, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer processLock.Close()

	credentialsDirectory := getenv(credentialsDirectoryEnvironment)
	if credentialsDirectory == "" {
		return fmt.Errorf("%s is not set; use systemd LoadCredential with %s and %s", credentialsDirectoryEnvironment, userUsernameCredentialName, userNewPasswordCredentialName)
	}
	usernameBytes, err := readCredential(credentialsDirectory, userUsernameCredentialName, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer erase(usernameBytes)
	passwordBytes, err := readCredential(credentialsDirectory, userNewPasswordCredentialName, uint32(effectiveUID))
	if err != nil {
		return err
	}
	defer erase(passwordBytes)

	if *dbFlag == "" {
		config.InitSetup(*configFlag, _confSample)
		*dbFlag = config.AppInfo.DBPath
	}
	if err := requireSealOutsideDatabase(*dbFlag, *sealFlag); err != nil {
		return err
	}
	db, err := sqlite.GetExistingDb(*dbFlag)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("access user database pool: %w", err)
	}
	defer sqlDB.Close()

	seal := userbootstrap.NewFileSeal(*sealFlag, uint32(effectiveUID))
	if err := service.ResetUserPassword(context.Background(), db, seal, string(usernameBytes), passwordBytes); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "user password reset completed")
	return nil
}

func readCredential(directory, name string, ownerUID uint32) ([]byte, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("credentials directory must be absolute")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect credentials directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return nil, errors.New("credentials directory must be a real directory, not a symlink")
	}
	if directoryInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credentials directory must not be accessible by group or other users")
	}
	if uid, ok := ownerUIDFromFileInfo(directoryInfo); !ok || uid != ownerUID {
		return nil, errors.New("credentials directory has an unexpected owner")
	}

	credentialPath := filepath.Join(directory, name)
	beforeOpen, err := os.Lstat(credentialPath)
	if err != nil {
		return nil, fmt.Errorf("inspect credential %s: %w", name, err)
	}
	if beforeOpen.Mode()&os.ModeSymlink != 0 || !beforeOpen.Mode().IsRegular() {
		return nil, fmt.Errorf("credential %s must be a regular file, not a symlink", name)
	}
	if beforeOpen.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential %s must not be accessible by group or other users", name)
	}
	if uid, ok := ownerUIDFromFileInfo(beforeOpen); !ok || uid != ownerUID {
		return nil, fmt.Errorf("credential %s has an unexpected owner", name)
	}

	fd, err := unix.Open(credentialPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open credential %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), credentialPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open credential %s", name)
	}
	defer file.Close()
	afterOpen, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open credential %s: %w", name, err)
	}
	if !os.SameFile(beforeOpen, afterOpen) || !afterOpen.Mode().IsRegular() {
		return nil, fmt.Errorf("credential %s changed while opening", name)
	}

	contents, err := io.ReadAll(io.LimitReader(file, maximumCredentialBytes+3))
	if err != nil {
		return nil, fmt.Errorf("read credential %s: %w", name, err)
	}
	if len(contents) > maximumCredentialBytes+2 {
		erase(contents)
		return nil, fmt.Errorf("credential %s exceeds %d bytes", name, maximumCredentialBytes)
	}
	contents = bytes.TrimSuffix(contents, []byte("\n"))
	contents = bytes.TrimSuffix(contents, []byte("\r"))
	if len(contents) == 0 || len(contents) > maximumCredentialBytes || bytes.IndexByte(contents, 0) >= 0 || bytes.IndexAny(contents, "\r\n") >= 0 {
		erase(contents)
		return nil, fmt.Errorf("credential %s is empty or contains forbidden bytes", name)
	}
	return contents, nil
}

func secureUserDataDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("administrator data path must be a real directory, not a symlink")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect administrator data path: %w", err)
	} else if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create administrator data path: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure administrator data path: %w", err)
	}
	return nil
}

func erase(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func ownerUIDFromFileInfo(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func requireSealOutsideDatabase(databaseDirectory, sealPath string) error {
	databaseAbsolute, err := resolveThroughExistingAncestor(databaseDirectory)
	if err != nil {
		return fmt.Errorf("resolve database directory: %w", err)
	}
	sealAbsolute, err := resolveThroughExistingAncestor(sealPath)
	if err != nil {
		return fmt.Errorf("resolve bootstrap seal: %w", err)
	}
	relative, err := filepath.Rel(databaseAbsolute, sealAbsolute)
	if err != nil {
		return fmt.Errorf("compare database and bootstrap seal paths: %w", err)
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
		return errors.New("bootstrap seal must be stored outside the database directory")
	}
	return nil
}

// resolveThroughExistingAncestor resolves every existing symlink component,
// then appends only the still-missing suffix. This makes separation checks
// reflect the physical ancestor tree rather than attacker-controlled spelling.
func resolveThroughExistingAncestor(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	probe := filepath.Clean(absolute)
	var missing []string
	for {
		if _, err := os.Lstat(probe); err == nil {
			resolved, err := filepath.EvalSymlinks(probe)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", errors.New("no existing path ancestor")
		}
		missing = append(missing, filepath.Base(probe))
		probe = parent
	}
}

func writeAddressFile(runtimePath string, filename string, address string) (string, error) {
	err := os.MkdirAll(runtimePath, 0o755)
	if err != nil {
		return "", err
	}

	filepath := filepath.Join(runtimePath, filename)
	return filepath, os.WriteFile(filepath, []byte(address), 0o600)
}
