//go:build !securityevents

package handlers

import "net/http"

type eventsStore struct{}

func (a *App) registerEventsRoutes(*http.ServeMux)          {}
func (a *App) StartEvents(string) (func(), error)           { return func() {}, nil }
func (a *App) eventsIssueGroups(*http.Request) []issueGroup { return nil }
