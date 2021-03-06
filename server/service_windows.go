// Copyright 2012-2017 Apcera Inc. All rights reserved.

package server

import (
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

const (
	serviceName     = "gnatsd"
	reopenLogCode   = 128
	reopenLogCmd    = svc.Cmd(reopenLogCode)
	acceptReopenLog = svc.Accepted(reopenLogCode)
)

// winServiceWrapper implements the svc.Handler interface for implementing
// gnatsd as a Windows service.
type winServiceWrapper struct {
	server *Server
}

// Execute will be called by the package code at the start of
// the service, and the service will exit once Execute completes.
// Inside Execute you must read service change requests from r and
// act accordingly. You must keep service control manager up to date
// about state of your service by writing into s as required.
// args contains service name followed by argument strings passed
// to the service.
// You can provide service exit code in exitCode return parameter,
// with 0 being "no error". You can also indicate if exit code,
// if any, is service specific or not by using svcSpecificEC
// parameter.
func (w *winServiceWrapper) Execute(args []string, changes <-chan svc.ChangeRequest,
	status chan<- svc.Status) (bool, uint32) {

	status <- svc.Status{State: svc.StartPending}
	go w.server.Start()

	// Wait for accept loop(s) to be started
	if !w.server.ReadyForConnections(10 * time.Second) {
		// Failed to start.
		return false, 1
	}

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange | acceptReopenLog,
	}

loop:
	for change := range changes {
		switch change.Cmd {
		case svc.Interrogate:
			status <- change.CurrentStatus
		case svc.Stop, svc.Shutdown:
			w.server.Shutdown()
			break loop
		case reopenLogCmd:
			// File log re-open for rotating file logs.
			w.server.ReOpenLogFile()
		case svc.ParamChange:
			if err := w.server.Reload(); err != nil {
				w.server.Errorf("Failed to reload server configuration: %s", err)
			}
		default:
			w.server.Debugf("Unexpected control request: %v", change.Cmd)
		}
	}

	status <- svc.Status{State: svc.StopPending}
	return false, 0
}

// Run starts the NATS server as a Windows service.
func Run(server *Server) error {
	run := svc.Run
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return err
	}
	if isInteractive {
		run = debug.Run
	}
	return run(serviceName, &winServiceWrapper{server})
}

// isWindowsService indicates if NATS is running as a Windows service.
func isWindowsService() bool {
	isInteractive, _ := svc.IsAnInteractiveSession()
	return !isInteractive
}
